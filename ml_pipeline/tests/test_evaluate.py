from pathlib import Path

import numpy as np
import onnx
import polars as pl
import pytest
from click.testing import CliRunner
from onnx import TensorProto, helper

from raptorgate_ml.cli import main
from raptorgate_ml.feature_vector import FIELD_NAMES
from raptorgate_ml.ml_model import (
    DEFAULT_ACCURACY_GATE,
    _gate_value,
    _metrics_from_confusion,
)


def _binary_metrics():
    matrix = np.asarray([[90, 10], [5, 95]])
    return _metrics_from_confusion(matrix, ["benign", "malicious"])


def test_gate_value_f1_malicious():
    metrics = _binary_metrics()
    metrics["binary"] = _binary_metrics()
    value = _gate_value(metrics, "f1_malicious")
    expected = metrics["binary"]["f1"]["malicious"]
    assert value == pytest.approx(expected)


def test_gate_value_accuracy():
    metrics = _binary_metrics()
    value = _gate_value(metrics, "accuracy")
    assert value == pytest.approx(metrics["accuracy"])


def test_gate_value_unknown_metric_raises():
    metrics = _binary_metrics()
    with pytest.raises(ValueError, match="unsupported gate metric"):
        _gate_value(metrics, "mcc")


def _build_constant_onnx(model_path: Path, num_labels: int) -> None:
    weight = np.zeros((len(FIELD_NAMES), num_labels), dtype=np.float32)
    bias = np.zeros((num_labels,), dtype=np.float32)
    graph = helper.make_graph(
        nodes=[
            helper.make_node("MatMul", ["features", "weight"], ["mm"]),
            helper.make_node("Add", ["mm", "bias"], ["logits"]),
        ],
        name="const",
        inputs=[helper.make_tensor_value_info("features", TensorProto.FLOAT, ["batch", len(FIELD_NAMES)])],
        outputs=[helper.make_tensor_value_info("logits", TensorProto.FLOAT, ["batch", num_labels])],
        initializer=[
            helper.make_tensor("weight", TensorProto.FLOAT, [len(FIELD_NAMES), num_labels], weight.tobytes(), raw=True),
            helper.make_tensor("bias", TensorProto.FLOAT, [num_labels], bias.tobytes(), raw=True),
        ],
    )
    onnx.save(helper.make_model(graph, opset_imports=[helper.make_opsetid("", 18)]), str(model_path))


def _training_frame(rows: int = 32) -> pl.DataFrame:
    data = {name: [0.0] * rows for name in FIELD_NAMES}
    data["label"] = ["benign"] * (rows // 2) + ["malicious"] * (rows // 2)
    data["attack_label"] = ["BENIGN"] * (rows // 2) + ["DDoS"] * (rows // 2)
    return pl.DataFrame(data)


def _write_model_with_metadata(model_path: Path) -> None:
    _build_constant_onnx(model_path, num_labels=2)
    import json

    metadata = {
        "architecture": "RaptorGateNet",
        "attack_labels": ["BENIGN", "DDoS"],
        "labels": ["BENIGN", "DDoS"],
        "benign_label": "BENIGN",
        "normalization": {
            "mean": [0.0] * len(FIELD_NAMES),
            "std": [1.0] * len(FIELD_NAMES),
        },
    }
    (model_path.parent / (model_path.name + ".json")).write_text(json.dumps(metadata))


def test_evaluate_cli_passes_above_gate(tmp_path: Path):
    train_path = tmp_path / "train.parquet"
    _training_frame().write_parquet(train_path)
    model_path = tmp_path / "model.onnx"
    _write_model_with_metadata(model_path)

    result = CliRunner().invoke(
        main,
        [
            "evaluate",
            "--model",
            str(model_path),
            "--parquet",
            str(train_path),
            "--gate",
            "0.0",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "passed=True" in result.output


def test_evaluate_cli_fails_below_gate(tmp_path: Path):
    train_path = tmp_path / "train.parquet"
    _training_frame().write_parquet(train_path)
    model_path = tmp_path / "model.onnx"
    _write_model_with_metadata(model_path)

    result = CliRunner().invoke(
        main,
        [
            "evaluate",
            "--model",
            str(model_path),
            "--parquet",
            str(train_path),
            "--gate",
            "0.99",
        ],
    )

    assert result.exit_code != 0
    assert "passed=False" in result.output


def test_evaluate_cli_default_gate_is_documented(tmp_path: Path):
    train_path = tmp_path / "train.parquet"
    _training_frame().write_parquet(train_path)
    model_path = tmp_path / "model.onnx"
    _write_model_with_metadata(model_path)

    result = CliRunner().invoke(
        main,
        [
            "evaluate",
            "--model",
            str(model_path),
            "--parquet",
            str(train_path),
        ],
    )

    assert f"threshold={DEFAULT_ACCURACY_GATE:.4f}" in result.output
