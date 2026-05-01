use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde_json::Value;
use tract_onnx::prelude::*;

const DEFAULT_THRESHOLD: f32 = 0.5;
const DEFAULT_ATTACK_CONFIDENCE_THRESHOLD: f32 = 0.5;
const UNKNOWN_ATTACK_TYPE: &str = "unknown";

type InferenceModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

#[derive(Debug, Clone)]
pub struct MlPrediction {
    pub malicious_score: f32,
    pub threshold: f32,
    pub model_checksum: String,
    pub attack_type: String,
}

pub trait MlPacketInspector: Send + Sync {
    fn inspect_features(&self, features: [f32; 38]) -> Result<Option<MlPrediction>>;
    fn is_enabled(&self) -> bool;
}

pub struct MlDetector {
    runtime: Option<MlRuntime>,
}

struct MlRuntime {
    model: Mutex<InferenceModel>,
    threshold: f32,
    attack_confidence_threshold: f32,
    model_checksum: String,
    labels: Vec<String>,
    benign_index: usize,
    supports_attack_labels: bool,
}

impl MlDetector {
    pub fn from_env() -> Self {
        if !env_flag("ML_ENABLED") {
            return Self::disabled();
        }

        match Self::load_from_env() {
            Ok(detector) => detector,
            Err(err) => {
                tracing::warn!(
                    event = "ml.detector.disabled",
                    error = %err,
                    "ML detector disabled"
                );
                Self::disabled()
            }
        }
    }

    pub const fn disabled() -> Self {
        Self { runtime: None }
    }

    fn load_from_env() -> Result<Self> {
        let model_path =
            env::var("ML_MODEL_PATH").context("ML_MODEL_PATH must be set when ML_ENABLED=true")?;
        let metadata_path = env::var("ML_MODEL_METADATA_PATH").ok();
        let metadata = metadata_path.as_deref().map(read_metadata).transpose()?;
        let threshold = resolve_threshold(metadata.as_ref())?;
        let attack_confidence_threshold = resolve_attack_confidence_threshold(metadata.as_ref())?;
        let model_checksum = metadata
            .as_ref()
            .and_then(metadata_checksum)
            .unwrap_or_else(|| {
                Path::new(&model_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            });
        let labels = metadata
            .as_ref()
            .and_then(metadata_labels)
            .unwrap_or_else(|| vec!["benign".to_string(), "malicious".to_string()]);
        let benign_index = labels
            .iter()
            .position(|label| label.eq_ignore_ascii_case("BENIGN"))
            .unwrap_or(0);
        let supports_attack_labels = metadata
            .as_ref()
            .is_some_and(|metadata| metadata.get("attack_labels").is_some() || labels.len() > 2);

        let model = load_model(&PathBuf::from(&model_path))?;

        tracing::info!(
            event = "ml.detector.enabled",
            model_path,
            threshold,
            attack_confidence_threshold,
            model_checksum,
            labels = ?labels,
            "ML detector enabled"
        );

        Ok(Self {
            runtime: Some(MlRuntime {
                model: Mutex::new(model),
                threshold,
                attack_confidence_threshold,
                model_checksum,
                labels,
                benign_index,
                supports_attack_labels,
            }),
        })
    }
}

impl MlPacketInspector for MlDetector {
    fn inspect_features(&self, features: [f32; 38]) -> Result<Option<MlPrediction>> {
        let Some(runtime) = &self.runtime else {
            return Ok(None);
        };

        let input = tract_ndarray::Array2::from_shape_vec((1, 38), features.to_vec())
            .context("failed to shape ML feature vector")?
            .into_tensor();
        let output = {
            let model = runtime
                .model
                .lock()
                .map_err(|_| anyhow::anyhow!("ML model lock poisoned"))?;
            model.run(tvec!(input.into()))?
        };
        let logits = output[0]
            .to_array_view::<f32>()
            .context("ML model output is not f32 logits")?;
        let logits = logits
            .as_slice()
            .context("ML model output logits are not contiguous")?;
        if logits.len() < 2 {
            anyhow::bail!(
                "ML model returned {} logits, expected at least 2",
                logits.len()
            );
        }

        let probs = softmax(logits);
        let malicious_score =
            if runtime.labels.len() == probs.len() && runtime.supports_attack_labels {
                malicious_score_from_probs(&probs, runtime.benign_index)
            } else {
                softmax_second(logits[0], logits[1])
            };
        if malicious_score < runtime.threshold {
            return Ok(None);
        }
        let attack_type = attack_type_from_probs(
            &probs,
            &runtime.labels,
            runtime.benign_index,
            runtime.attack_confidence_threshold,
            runtime.supports_attack_labels,
        );

        Ok(Some(MlPrediction {
            malicious_score,
            threshold: runtime.threshold,
            model_checksum: runtime.model_checksum.clone(),
            attack_type,
        }))
    }

    fn is_enabled(&self) -> bool {
        self.runtime.is_some()
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false)
}

fn read_metadata(path: &str) -> Result<Value> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read ML metadata at {path}"))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse ML metadata at {path}"))
}

fn metadata_threshold(metadata: &Value) -> Option<f32> {
    metadata
        .pointer("/test_metrics/calibration/best_f1_malicious/threshold")
        .and_then(Value::as_f64)
        .map(|value| value as f32)
}

fn metadata_checksum(metadata: &Value) -> Option<String> {
    metadata
        .get("checksum_sha256")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn metadata_labels(metadata: &Value) -> Option<Vec<String>> {
    let values = metadata
        .get("attack_labels")
        .or_else(|| metadata.get("labels"))?
        .as_array()?;
    let labels = values
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if labels.len() >= 2 {
        Some(labels)
    } else {
        None
    }
}

fn resolve_threshold(metadata: Option<&Value>) -> Result<f32> {
    match env::var("ML_ALERT_THRESHOLD") {
        Ok(raw) => raw
            .parse::<f32>()
            .with_context(|| format!("ML_ALERT_THRESHOLD must be a float, got `{raw}`")),
        Err(env::VarError::NotPresent) => Ok(metadata
            .and_then(metadata_threshold)
            .unwrap_or(DEFAULT_THRESHOLD)),
        Err(err) => Err(err).context("failed to read ML_ALERT_THRESHOLD"),
    }
}

fn metadata_attack_confidence_threshold(metadata: &Value) -> Option<f32> {
    metadata
        .get("attack_confidence_threshold")
        .and_then(Value::as_f64)
        .map(|value| value as f32)
}

fn resolve_attack_confidence_threshold(metadata: Option<&Value>) -> Result<f32> {
    match env::var("ML_ATTACK_CONFIDENCE_THRESHOLD") {
        Ok(raw) => raw.parse::<f32>().with_context(|| {
            format!("ML_ATTACK_CONFIDENCE_THRESHOLD must be a float, got `{raw}`")
        }),
        Err(env::VarError::NotPresent) => Ok(metadata
            .and_then(metadata_attack_confidence_threshold)
            .unwrap_or(DEFAULT_ATTACK_CONFIDENCE_THRESHOLD)),
        Err(err) => Err(err).context("failed to read ML_ATTACK_CONFIDENCE_THRESHOLD"),
    }
}

fn load_model(path: &Path) -> Result<InferenceModel> {
    tract_onnx::onnx()
        .model_for_path(path)
        .with_context(|| format!("failed to load ONNX model at {}", path.display()))?
        .into_optimized()
        .context("failed to optimize ML model")?
        .into_runnable()
        .context("failed to prepare ML model runtime")
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut exp = logits
        .iter()
        .map(|value| (value - max).exp())
        .collect::<Vec<_>>();
    let sum = exp.iter().sum::<f32>();
    if sum > 0.0 {
        for value in &mut exp {
            *value /= sum;
        }
    }
    exp
}

fn softmax_second(first: f32, second: f32) -> f32 {
    let max = first.max(second);
    let first = (first - max).exp();
    let second = (second - max).exp();
    second / (first + second)
}

fn malicious_score_from_probs(probs: &[f32], benign_index: usize) -> f32 {
    probs
        .iter()
        .enumerate()
        .filter_map(|(i, prob)| (i != benign_index).then_some(*prob))
        .sum()
}

fn attack_type_from_probs(
    probs: &[f32],
    labels: &[String],
    benign_index: usize,
    attack_confidence_threshold: f32,
    supports_attack_labels: bool,
) -> String {
    if !supports_attack_labels || labels.len() != probs.len() {
        return UNKNOWN_ATTACK_TYPE.to_string();
    }
    let Some((best_index, best_score)) = probs
        .iter()
        .copied()
        .enumerate()
        .filter(|(i, _)| *i != benign_index)
        .max_by(|(_, left), (_, right)| left.total_cmp(right))
    else {
        return UNKNOWN_ATTACK_TYPE.to_string();
    };
    if best_score < attack_confidence_threshold {
        return UNKNOWN_ATTACK_TYPE.to_string();
    }
    labels
        .get(best_index)
        .cloned()
        .unwrap_or_else(|| UNKNOWN_ATTACK_TYPE.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_second_is_stable_for_large_logits() {
        let score = softmax_second(1000.0, 1001.0);
        assert!((score - 0.731_058_6).abs() < 1e-5);
    }

    #[test]
    fn metadata_threshold_reads_calibrated_path() {
        let metadata = serde_json::json!({
            "test_metrics": {
                "calibration": {
                    "best_f1_malicious": {
                        "threshold": 0.2
                    }
                }
            }
        });

        assert_eq!(metadata_threshold(&metadata), Some(0.2));
    }

    #[test]
    fn metadata_labels_prefers_attack_labels() {
        let metadata = serde_json::json!({
            "labels": ["benign", "malicious"],
            "attack_labels": ["BENIGN", "DDoS", "PortScan"]
        });

        assert_eq!(
            metadata_labels(&metadata),
            Some(vec![
                "BENIGN".to_string(),
                "DDoS".to_string(),
                "PortScan".to_string()
            ])
        );
    }

    #[test]
    fn multiclass_scores_sum_non_benign_probabilities() {
        let labels = vec![
            "BENIGN".to_string(),
            "DDoS".to_string(),
            "PortScan".to_string(),
        ];
        let probs = softmax(&[3.0, 2.0, 1.0]);
        let score = malicious_score_from_probs(&probs, 0);

        assert!((score - (probs[1] + probs[2])).abs() < 1e-6);
        assert_eq!(
            attack_type_from_probs(&probs, &labels, 0, 0.2, true),
            "DDoS"
        );
    }

    #[test]
    fn low_attack_confidence_returns_unknown() {
        let labels = vec![
            "BENIGN".to_string(),
            "DDoS".to_string(),
            "PortScan".to_string(),
        ];
        let probs = softmax(&[3.0, 2.0, 1.0]);

        assert_eq!(
            attack_type_from_probs(&probs, &labels, 0, 0.9, true),
            UNKNOWN_ATTACK_TYPE
        );
    }

    #[test]
    fn binary_model_attack_type_returns_unknown() {
        let labels = vec!["benign".to_string(), "malicious".to_string()];
        let probs = softmax(&[0.0, 3.0]);

        assert_eq!(
            attack_type_from_probs(&probs, &labels, 0, 0.5, false),
            UNKNOWN_ATTACK_TYPE
        );
    }

    #[test]
    fn checked_in_v5_model_loads_and_scores_zero_vector_when_available() {
        let model_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../ml_pipeline/data/models/raptorgate-cicids2017-v5-attacks.onnx");
        if !model_path.exists() {
            return;
        }

        let model = load_model(&model_path).unwrap();
        let input = tract_ndarray::Array2::from_shape_vec((1, 38), vec![0.0f32; 38])
            .unwrap()
            .into_tensor();
        let output = model.run(tvec!(input.into())).unwrap();
        let logits = output[0].to_array_view::<f32>().unwrap();

        assert_eq!(logits.len(), 14);
    }
}
