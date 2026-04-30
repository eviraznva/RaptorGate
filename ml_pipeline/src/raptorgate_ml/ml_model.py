from __future__ import annotations

import hashlib
import json
import logging
import time
import warnings
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import numpy as np
import pyarrow.parquet as pq
import torch
from torch import nn
from torch.export import Dim

from raptorgate_ml.feature_vector import FIELD_NAMES

LABELS: tuple[str, str] = ("benign", "malicious")
LABEL_TO_ID = {label: i for i, label in enumerate(LABELS)}
INPUT_SIZE = len(FIELD_NAMES)
LossName = Literal["weighted_ce", "focal"]


@dataclass
class TrainConfig:
    train_path: Path
    out_path: Path
    test_path: Path | None = None
    metadata_path: Path | None = None
    epochs: int = 10
    batch_size: int = 65_536
    seed: int = 42
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    dropout: float = 0.15
    width: int = 256
    residual_blocks: int = 4
    loss: LossName = "weighted_ce"
    focal_gamma: float = 2.0
    amp: bool = True


@dataclass
class TrainResult:
    out_path: Path
    metadata_path: Path
    checksum: str
    train_rows: int
    train_class_counts: dict[str, int]
    test_metrics: dict[str, object] | None


class ResidualBlock(nn.Module):
    def __init__(self, width: int, dropout: float) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(width, width),
            nn.BatchNorm1d(width),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(width, width),
            nn.BatchNorm1d(width),
        )
        self.activation = nn.GELU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.activation(x + self.net(x))


class RaptorGateNet(nn.Module):
    def __init__(
        self,
        mean: torch.Tensor | None = None,
        std: torch.Tensor | None = None,
        dropout: float = 0.15,
        width: int = 256,
        residual_blocks: int = 4,
    ) -> None:
        super().__init__()
        if width < 16:
            raise ValueError("width must be at least 16")
        if residual_blocks < 0:
            raise ValueError("residual_blocks must be greater than or equal to 0")
        self.register_buffer(
            "feature_mean",
            torch.zeros(INPUT_SIZE, dtype=torch.float32) if mean is None else mean.float(),
        )
        self.register_buffer(
            "feature_std",
            torch.ones(INPUT_SIZE, dtype=torch.float32) if std is None else std.float(),
        )
        self.input = nn.Sequential(
            nn.Linear(INPUT_SIZE, width),
            nn.BatchNorm1d(width),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.residual_blocks = nn.ModuleList(
            ResidualBlock(width, dropout) for _ in range(residual_blocks)
        )
        head_width = max(16, width // 2)
        self.head = nn.Sequential(
            nn.Linear(width, head_width),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(head_width, len(LABELS)),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = (x - self.feature_mean) / self.feature_std
        x = self.input(x)
        for block in self.residual_blocks:
            x = block(x)
        return self.head(x)


class FocalLoss(nn.Module):
    def __init__(self, weight: torch.Tensor, gamma: float) -> None:
        super().__init__()
        self.register_buffer("weight", weight)
        self.gamma = gamma

    def forward(self, logits: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        log_prob = nn.functional.log_softmax(logits, dim=1)
        ce = nn.functional.nll_loss(log_prob, target, reduction="none")
        pt = torch.exp(-ce)
        weights = self.weight.gather(0, target)
        return (weights * ((1.0 - pt) ** self.gamma) * ce).mean()


def _validate_schema(path: Path) -> None:
    schema = pq.ParquetFile(path).schema_arrow
    columns = set(schema.names)
    missing = [name for name in [*FIELD_NAMES, "label"] if name not in columns]
    if missing:
        raise ValueError(f"{path} is missing required columns: {', '.join(missing)}")


def _encode_labels(values: np.ndarray) -> np.ndarray:
    encoded = np.empty(len(values), dtype=np.int64)
    for i, raw in enumerate(values):
        label = str(raw)
        if label not in LABEL_TO_ID:
            raise ValueError(f"unsupported label: {label}")
        encoded[i] = LABEL_TO_ID[label]
    return encoded


def _iter_batches(path: Path, batch_size: int) -> Iterator[tuple[np.ndarray, np.ndarray]]:
    _validate_schema(path)
    parquet = pq.ParquetFile(path)
    for batch in parquet.iter_batches(batch_size=batch_size, columns=[*FIELD_NAMES, "label"]):
        columns = [
            batch.column(batch.schema.get_field_index(name)).to_numpy(zero_copy_only=False)
            for name in FIELD_NAMES
        ]
        x = np.column_stack(columns).astype(np.float32, copy=False)
        labels = np.array(
            batch.column(batch.schema.get_field_index("label")).to_pylist(),
            dtype=object,
        )
        yield x, _encode_labels(labels)


def _scan_training_stats(
    path: Path,
    batch_size: int,
    log: Callable[[str], None],
) -> tuple[np.ndarray, np.ndarray, int, dict[str, int]]:
    rows = 0
    sums = np.zeros(INPUT_SIZE, dtype=np.float64)
    sumsq = np.zeros(INPUT_SIZE, dtype=np.float64)
    counts = {label: 0 for label in LABELS}

    for batch_no, (x, y) in enumerate(_iter_batches(path, batch_size), start=1):
        rows += len(x)
        sums += x.sum(axis=0, dtype=np.float64)
        sumsq += np.square(x, dtype=np.float64).sum(axis=0, dtype=np.float64)
        for label, label_id in LABEL_TO_ID.items():
            counts[label] += int(np.count_nonzero(y == label_id))
        log(f"stats batch={batch_no} rows={rows}")

    if rows == 0:
        raise ValueError(f"{path} does not contain training rows")
    if any(counts[label] == 0 for label in LABELS):
        raise ValueError(f"{path} must contain both labels: {', '.join(LABELS)}")

    mean = sums / rows
    variance = np.maximum((sumsq / rows) - np.square(mean), 1e-12)
    std = np.sqrt(variance)
    return mean.astype(np.float32), std.astype(np.float32), rows, counts


def _metrics_from_confusion(matrix: np.ndarray) -> dict[str, object]:
    total = int(matrix.sum())
    correct = int(np.trace(matrix))
    precision: dict[str, float] = {}
    recall: dict[str, float] = {}
    f1: dict[str, float] = {}
    for i, label in enumerate(LABELS):
        tp = float(matrix[i, i])
        fp = float(matrix[:, i].sum() - matrix[i, i])
        fn = float(matrix[i, :].sum() - matrix[i, i])
        precision[label] = tp / (tp + fp) if tp + fp else 0.0
        recall[label] = tp / (tp + fn) if tp + fn else 0.0
        f1[label] = (
            2.0 * precision[label] * recall[label] / (precision[label] + recall[label])
            if precision[label] + recall[label]
            else 0.0
        )
    return {
        "accuracy": correct / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": matrix.astype(int).tolist(),
        "rows": total,
    }


def _confusion_from_arrays(y_true: np.ndarray, y_pred: np.ndarray) -> np.ndarray:
    encoded = y_true.astype(np.int64) * len(LABELS) + y_pred.astype(np.int64)
    return np.bincount(encoded, minlength=len(LABELS) ** 2).reshape(len(LABELS), len(LABELS))


def _to_device(array: np.ndarray, device: torch.device, pin_memory: bool = True) -> torch.Tensor:
    tensor = torch.from_numpy(array)
    if pin_memory and device.type == "cuda":
        tensor = tensor.pin_memory()
    return tensor.to(device, non_blocking=pin_memory and device.type == "cuda")


def _amp_enabled(config: TrainConfig, device: torch.device) -> bool:
    return config.amp and device.type == "cuda"


def _calibrate_thresholds(
    y_true: np.ndarray,
    malicious_prob: np.ndarray,
) -> dict[str, object]:
    thresholds = np.linspace(0.05, 0.95, 91, dtype=np.float32)
    best_f1: dict[str, object] | None = None
    best_recall_at_precision: dict[str, object] | None = None

    for threshold in thresholds:
        pred = (malicious_prob >= threshold).astype(np.int64)
        metrics = _metrics_from_confusion(_confusion_from_arrays(y_true, pred))
        item = {
            "threshold": float(threshold),
            "accuracy": metrics["accuracy"],
            "precision_malicious": metrics["precision"]["malicious"],
            "recall_malicious": metrics["recall"]["malicious"],
            "f1_malicious": metrics["f1"]["malicious"],
            "confusion_matrix": metrics["confusion_matrix"],
        }
        if best_f1 is None or item["f1_malicious"] > best_f1["f1_malicious"]:
            best_f1 = item
        if item["precision_malicious"] >= 0.99 and (
            best_recall_at_precision is None
            or item["recall_malicious"] > best_recall_at_precision["recall_malicious"]
        ):
            best_recall_at_precision = item

    return {
        "best_f1_malicious": best_f1,
        "best_recall_malicious_at_precision_0_99": best_recall_at_precision,
    }


def _evaluate_model(
    model: RaptorGateNet,
    path: Path,
    batch_size: int,
    device: torch.device,
    config: TrainConfig,
) -> dict[str, object]:
    model.eval()
    y_parts: list[np.ndarray] = []
    pred_parts: list[np.ndarray] = []
    prob_parts: list[np.ndarray] = []
    use_amp = _amp_enabled(config, device)
    with torch.no_grad():
        for x, y in _iter_batches(path, batch_size):
            x_tensor = _to_device(x, device)
            with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=use_amp):
                logits = model(x_tensor)
            probs = torch.softmax(logits.float(), dim=1)
            y_parts.append(y.astype(np.int64, copy=False))
            pred_parts.append(torch.argmax(probs, dim=1).cpu().numpy())
            prob_parts.append(probs[:, LABEL_TO_ID["malicious"]].cpu().numpy().astype(np.float32))
    if not y_parts:
        raise ValueError(f"{path} does not contain evaluation rows")
    y_true = np.concatenate(y_parts)
    pred = np.concatenate(pred_parts)
    malicious_prob = np.concatenate(prob_parts)
    matrix = _confusion_from_arrays(y_true, pred)
    if matrix.sum() == 0:
        raise ValueError(f"{path} does not contain evaluation rows")
    metrics = _metrics_from_confusion(matrix)
    metrics["decision"] = "argmax"
    metrics["calibration"] = _calibrate_thresholds(y_true, malicious_prob)
    return metrics


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cuda_device() -> torch.device:
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA GPU is required for training but torch.cuda.is_available() is false")
    return torch.device("cuda")


def _criterion(config: TrainConfig, class_weights: torch.Tensor) -> nn.Module:
    if config.loss == "weighted_ce":
        return nn.CrossEntropyLoss(weight=class_weights)
    if config.loss == "focal":
        return FocalLoss(weight=class_weights, gamma=config.focal_gamma)
    raise ValueError(f"unsupported loss: {config.loss}")


@contextmanager
def _quiet_onnx_export() -> Iterator[None]:
    logger_name = "torch.onnx._internal.exporter._registration"
    exporter_logger = logging.getLogger(logger_name)
    previous_level = exporter_logger.level
    exporter_logger.setLevel(logging.ERROR)
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r"`isinstance\(treespec, LeafSpec\)` is deprecated.*",
                category=FutureWarning,
            )
            yield
    finally:
        exporter_logger.setLevel(previous_level)


def train_model(
    config: TrainConfig,
    log: Callable[[str], None] | None = None,
) -> TrainResult:
    logger = log or (lambda _: None)
    metadata_path = config.metadata_path or config.out_path.with_suffix(config.out_path.suffix + ".json")
    config.out_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(config.seed)
    device = _cuda_device()
    props = torch.cuda.get_device_properties(device)
    logger(
        "gpu "
        f"name={torch.cuda.get_device_name(device)} "
        f"memory_gb={props.total_memory / (1024 ** 3):.2f}"
    )
    logger(f"training train={config.train_path} out={config.out_path}")
    logger(
        "config "
        f"epochs={config.epochs} batch_size={config.batch_size} "
        f"lr={config.learning_rate} weight_decay={config.weight_decay} "
        f"dropout={config.dropout} width={config.width} "
        f"residual_blocks={config.residual_blocks} loss={config.loss} "
        f"amp={config.amp} seed={config.seed}"
    )

    mean, std, train_rows, train_class_counts = _scan_training_stats(
        config.train_path,
        config.batch_size,
        logger,
    )
    logger(f"train rows={train_rows} class_counts={train_class_counts}")

    model = RaptorGateNet(
        mean=torch.from_numpy(mean),
        std=torch.from_numpy(std),
        dropout=config.dropout,
        width=config.width,
        residual_blocks=config.residual_blocks,
    ).to(device)
    class_weights = torch.tensor(
        [
            train_rows / (len(LABELS) * train_class_counts[label])
            for label in LABELS
        ],
        dtype=torch.float32,
        device=device,
    )
    criterion = _criterion(config, class_weights)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=config.learning_rate,
        weight_decay=config.weight_decay,
    )
    use_amp = _amp_enabled(config, device)
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)

    for epoch in range(1, config.epochs + 1):
        model.train()
        started = time.perf_counter()
        rows = 0
        correct = 0
        batches = 0
        loss_sum = 0.0
        for x, y in _iter_batches(config.train_path, config.batch_size):
            if len(y) < 2:
                continue
            x_tensor = _to_device(x, device)
            y_tensor = _to_device(y, device)
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=use_amp):
                logits = model(x_tensor)
                loss = criterion(logits, y_tensor)
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()

            pred = torch.argmax(logits.detach(), dim=1)
            correct += int((pred == y_tensor).sum().item())
            rows += len(y)
            batches += 1
            loss_sum += float(loss.item()) * len(y)
        if rows == 0:
            raise ValueError("training produced no usable batches")
        elapsed = max(time.perf_counter() - started, 1e-9)
        logger(
            f"epoch={epoch}/{config.epochs} batches={batches} rows={rows} "
            f"loss={loss_sum / rows:.6f} accuracy={correct / rows:.4f} "
            f"rows_per_sec={rows / elapsed:.0f} "
            f"lr={optimizer.param_groups[0]['lr']:.6g}"
        )

    test_metrics = None
    if config.test_path is not None:
        test_metrics = _evaluate_model(model, config.test_path, config.batch_size, device, config)
        logger(
            "test "
            f"rows={test_metrics['rows']} "
            f"accuracy={test_metrics['accuracy']:.4f} "
            f"f1_malicious={test_metrics['f1']['malicious']:.4f} "
            f"confusion_matrix={test_metrics['confusion_matrix']}"
        )
        best = test_metrics["calibration"]["best_f1_malicious"]
        if best is not None:
            logger(
                "calibration "
                f"best_f1_threshold={best['threshold']:.2f} "
                f"f1_malicious={best['f1_malicious']:.4f} "
                f"recall_malicious={best['recall_malicious']:.4f} "
                f"precision_malicious={best['precision_malicious']:.4f}"
            )

    model.eval()
    dummy = torch.zeros(1, INPUT_SIZE, dtype=torch.float32, device=device)
    with _quiet_onnx_export():
        torch.onnx.export(
            model,
            dummy,
            str(config.out_path),
            input_names=["features"],
            output_names=["logits"],
            dynamic_shapes=({0: Dim("batch", min=1)},),
            opset_version=18,
            verbose=False,
        )
    checksum = _sha256(config.out_path)

    metadata = {
        "created_at": datetime.now(UTC).isoformat(),
        "artifact": str(config.out_path),
        "checksum_sha256": checksum,
        "architecture": "RaptorGateNet",
        "architecture_version": 2,
        "architecture_config": {
            "width": config.width,
            "residual_blocks": config.residual_blocks,
        },
        "feature_names": FIELD_NAMES,
        "normalization": {
            "mean": mean.astype(float).tolist(),
            "std": std.astype(float).tolist(),
        },
        "labels": list(LABELS),
        "train_rows": train_rows,
        "train_class_counts": train_class_counts,
        "epochs": config.epochs,
        "batch_size": config.batch_size,
        "seed": config.seed,
        "learning_rate": config.learning_rate,
        "weight_decay": config.weight_decay,
        "dropout": config.dropout,
        "loss": config.loss,
        "focal_gamma": config.focal_gamma,
        "amp": config.amp,
        "test_metrics": test_metrics,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    logger(f"saved model={config.out_path} metadata={metadata_path} checksum={checksum}")

    return TrainResult(
        out_path=config.out_path,
        metadata_path=metadata_path,
        checksum=checksum,
        train_rows=train_rows,
        train_class_counts=train_class_counts,
        test_metrics=test_metrics,
    )
