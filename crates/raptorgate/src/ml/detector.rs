use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde_json::Value;
use tract_onnx::prelude::*;

const DEFAULT_THRESHOLD: f32 = 0.5;

type InferenceModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

#[derive(Debug, Clone)]
pub struct MlPrediction {
    pub malicious_score: f32,
    pub threshold: f32,
    pub model_checksum: String,
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
    model_checksum: String,
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

        let model = load_model(&PathBuf::from(&model_path))?;

        tracing::info!(
            event = "ml.detector.enabled",
            model_path,
            threshold,
            model_checksum,
            "ML detector enabled"
        );

        Ok(Self {
            runtime: Some(MlRuntime {
                model: Mutex::new(model),
                threshold,
                model_checksum,
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

        let malicious_score = softmax_second(logits[0], logits[1]);
        if malicious_score < runtime.threshold {
            return Ok(None);
        }

        Ok(Some(MlPrediction {
            malicious_score,
            threshold: runtime.threshold,
            model_checksum: runtime.model_checksum.clone(),
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

fn load_model(path: &Path) -> Result<InferenceModel> {
    tract_onnx::onnx()
        .model_for_path(path)
        .with_context(|| format!("failed to load ONNX model at {}", path.display()))?
        .into_optimized()
        .context("failed to optimize ML model")?
        .into_runnable()
        .context("failed to prepare ML model runtime")
}

fn softmax_second(first: f32, second: f32) -> f32 {
    let max = first.max(second);
    let first = (first - max).exp();
    let second = (second - max).exp();
    second / (first + second)
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
    fn checked_in_v4_model_loads_and_scores_zero_vector_when_available() {
        let model_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../ml_pipeline/data/models/raptorgate-cicids2017-v4-focal.onnx");
        if !model_path.exists() {
            return;
        }

        let model = load_model(&model_path).unwrap();
        let input = tract_ndarray::Array2::from_shape_vec((1, 38), vec![0.0f32; 38])
            .unwrap()
            .into_tensor();
        let output = model.run(tvec!(input.into())).unwrap();
        let logits = output[0].to_array_view::<f32>().unwrap();

        assert_eq!(logits.len(), 2);
    }
}
