# RaptorGate ML Pipeline

Train a traffic-classification model for the RaptorGate firewall. The pipeline is a
three-stage CLI: download raw PCAPs, build a labeled feature Parquet, train an ONNX
classifier. Training is **GPU-only** (CUDA) and requires Python 3.12+.

## Layout

```
ml_pipeline/
├── pyproject.toml
├── src/raptorgate_ml/
│   ├── cli.py              # `raptorgate-ml` entry point (download / build / train / stats)
│   ├── datasets.py         # CIC-IDS-2017 downloader (resume, magic-byte validation)
│   ├── pcap_reader.py      # Scapy packet parser
│   ├── dpi.py              # L7 protocol detection (TLS, HTTP, DNS, ...)
│   ├── flow_stats.py       # 60s sliding-window per-source stats
│   ├── feature_vector.py   # 38-field feature vector
│   ├── labeling.py         # 5-tuple → CIC-IDS-2017 label lookup
│   ├── pipeline.py         # PCAP → Parquet builder, stratified train/test split
│   └── ml_model.py         # RaptorGateNet architecture, training loop, ONNX export
└── tests/
```

## Prerequisites

- Python 3.12+
- NVIDIA GPU with CUDA toolkit installed
- `uv` (recommended) or `pip`

```bash
cd ml_pipeline
uv sync                    # or: pip install -e ".[dev]"
```

Verify CUDA is visible to PyTorch:

```bash
python -c "import torch; assert torch.cuda.is_available(); print(torch.cuda.get_device_name(0))"
```

## Step 1 — Download the dataset

The pipeline trains on **CIC-IDS-2017** (Canadian Institute for Cybersecurity, 2017).
It tries the official CIC hosts first, then falls back to a HuggingFace mirror. Each
file is validated by magic bytes before being accepted.

```bash
raptorgate-ml download --dataset cicids2017 --target ./data/raw
```

This fetches five daily PCAPs (Monday–Friday) and the
`GeneratedLabelledFlows` label archive. Re-running the command is safe — partial
downloads are resumed via HTTP `Range` and already-valid files are skipped.

## Step 2 — Build the training Parquet

Each packet is converted into a 38-feature vector and joined to a CIC label by its
5-tuple (src/dst IP + ports + L4 proto) and timestamp window. Per-source stats
(unique destinations, SYN rate, NXDOMAIN ratio, new-flow rate) are aggregated in a
60-second sliding window. Rows are written per-PCAP, then concatenated into a
single zstd-compressed Parquet.

```bash
raptorgate-ml build \
  --pcap-dir ./data/raw \
  --labels-dir ./data/raw/GeneratedLabelledFlows \
  --out ./data/train.parquet \
  --test-out ./data/test.parquet \
  --test-ratio 0.2 \
  --window 60 \
  --jobs 4
```

Key flags:

- `--test-ratio` — default 0.2. The split is **stratified by `attack_label`** and
  grouped by `flow_id`, so a flow's packets all land on the same side of the split.
- `--window` — sliding-window length in seconds for per-source aggregates (default 60).
- `--jobs` — parallel workers across PCAPs. Each worker runs in a `spawn` process,
  so memory scales linearly with the number of PCAPs.
- `--include-unmatched` — by default, packets without a CIC label are dropped.

Inspect the result:

```bash
raptorgate-ml stats --parquet ./data/train.parquet
```

## Step 3 — Train the model

`RaptorGateNet` is an MLP with `N` residual blocks: `Linear → BatchNorm → GELU →
Dropout` on the input projection, then `N` blocks of
`Linear → BN → GELU → Dropout → Linear → BN` with a skip connection, and a
two-layer classification head. Input normalization (mean/std computed over the
training set) is baked into the model as non-trainable buffers, so the exported
ONNX takes raw features.

```bash
raptorgate-ml train \
  --train ./data/train.parquet \
  --test  ./data/test.parquet \
  --out   ./data/model.onnx \
  --metadata-out ./data/model.onnx.json \
  --epochs 35 \
  --batch-size 131072 \
  --learning-rate 3e-4 \
  --weight-decay 5e-5 \
  --dropout 0.08 \
  --width 256 \
  --residual-blocks 4 \
  --loss focal \
  --focal-gamma 1.5 \
  --amp \
  --attack-confidence-threshold 0.5
```

Defaults are tuned for the v4 binary model; v5 (multi-class) used the same
recipe. Loss options:

- `weighted_ce` — class-balanced cross-entropy.
- `focal` — focal loss (Lin et al., 2017) with `--focal-gamma` (default 2.0).
  Recommended for the heavy class imbalance in CIC-IDS-2017.

Training uses AMP (fp16) on CUDA, AdamW, and a large batch size (65k–131k) so the
GPU stays busy. Class weights are computed as
`N / (C * count[c])` from the training set. After the last epoch, the model is
evaluated on the test set, decision thresholds are calibrated (best F1 and
best-recall-at-precision-0.99 for the binary `malicious` score), and the result
is exported to ONNX opset 18 with a dynamic batch dimension.

## Outputs

```
data/model.onnx         # RaptorGateNet, ONNX opset 18, dynamic batch
data/model.onnx.json    # metadata: arch, normalization, labels, metrics
```

The metadata JSON is what the Rust inference side reads to reconstruct the model
contract. It includes:

- `architecture`, `architecture_config` (width, residual blocks, num labels)
- `normalization.mean` / `normalization.std` (length 38)
- `labels` / `attack_labels` (e.g. `["BENIGN", "Bot", "DDoS", ...]`)
- `attack_confidence_threshold`
- `train_rows`, `train_class_counts`
- `test_metrics` — full multi-class confusion matrix plus binary
  (benign/malicious) accuracy, precision, recall, F1, and the calibrated
  threshold candidates
- `checksum_sha256` of the ONNX file

## Dropping the model into RaptorGate

Point the `ml_model` block in the firewall's configuration at the new artifact
and restart the data plane. The detector (`crates/raptorgate/src/ml/detector.rs`)
loads ONNX via `tract_onnx`, applies the stored softmax, sums the attack-class
probabilities, and compares against `attack_confidence_threshold`. Any change to
`labels` or `normalization` must be reflected on both sides; the metadata file
is the source of truth.

## Reproducing a shipped model

The pre-trained artifacts in `ml_pipeline/data/models/` were produced by the
commands above with the hyperparameters in the corresponding `*.onnx.json`. To
reproduce from scratch, delete `data/`, re-run the three steps, and verify the
new metadata's `checksum_sha256` and `test_metrics` match.
