import json
from pathlib import Path

import polars as pl
import pytest
import torch
from click.testing import CliRunner

from raptorgate_ml.cli import main
from raptorgate_ml.feature_vector import FIELD_NAMES
from raptorgate_ml.ml_model import RaptorGateNet, TrainConfig, _validate_schema, train_model


def _training_frame() -> pl.DataFrame:
    data = {name: [0.0, 0.1, 0.2, 2.0, 2.1, 2.2] for name in FIELD_NAMES}
    data["proto"] = [1.0, 1.0, 1.0, 2.0, 2.0, 2.0]
    data["dst_port_log"] = [4.0, 4.1, 4.2, 8.0, 8.1, 8.2]
    data["label"] = ["benign", "benign", "benign", "malicious", "malicious", "malicious"]
    return pl.DataFrame(data)


def test_raptorgate_net_forward_shape():
    model = RaptorGateNet()
    model.eval()
    with torch.no_grad():
        logits = model(torch.zeros(4, len(FIELD_NAMES), dtype=torch.float32))
    assert logits.shape == (4, 2)


def test_train_cli_requires_cuda(tmp_path: Path):
    train_path = tmp_path / "train.parquet"
    _training_frame().write_parquet(train_path)

    result = CliRunner().invoke(
        main,
        [
            "train",
            "--train",
            str(train_path),
            "--out",
            str(tmp_path / "model.onnx"),
            "--epochs",
            "1",
            "--batch-size",
            "2",
        ],
    )

    if torch.cuda.is_available():
        assert result.exit_code == 0, result.output
    else:
        assert result.exit_code != 0
        assert "CUDA GPU is required" in result.output


def test_train_schema_rejects_missing_feature_column(tmp_path: Path):
    train_path = tmp_path / "train.parquet"
    pl.DataFrame({"label": ["benign"]}).write_parquet(train_path)

    with pytest.raises(ValueError, match="missing required columns"):
        _validate_schema(train_path)


@pytest.mark.skipif(not torch.cuda.is_available(), reason="CUDA GPU is required")
def test_train_model_writes_onnx_and_metadata_on_cuda(tmp_path: Path):
    train_path = tmp_path / "train.parquet"
    test_path = tmp_path / "test.parquet"
    _training_frame().write_parquet(train_path)
    _training_frame().write_parquet(test_path)

    result = train_model(
        TrainConfig(
            train_path=train_path,
            test_path=test_path,
            out_path=tmp_path / "model.onnx",
            epochs=1,
            batch_size=2,
            seed=7,
        )
    )

    metadata = json.loads(result.metadata_path.read_text())
    assert result.out_path.exists()
    assert result.out_path.stat().st_size > 0
    assert len(result.checksum) == 64
    assert metadata["architecture"] == "RaptorGateNet"
    assert metadata["feature_names"] == FIELD_NAMES
    assert metadata["labels"] == ["benign", "malicious"]
    assert metadata["train_rows"] == 6
    assert metadata["test_metrics"]["rows"] == 6
