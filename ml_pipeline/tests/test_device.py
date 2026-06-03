import pytest
import torch

from raptorgate_ml.ml_model import (
    DEFAULT_ACCURACY_GATE,
    _is_cuda_device,
    _pick_device,
    _autocast_device_type,
)


def test_pick_device_auto_returns_cuda_when_available(monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    assert _pick_device("auto").type == "cuda"
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    with pytest.raises(RuntimeError, match="no GPU available"):
        _pick_device("auto")


def test_pick_device_cpu_always_succeeds():
    device = _pick_device("cpu")
    assert device.type == "cpu"


def test_pick_device_explicit_cuda_fails_without_gpu(monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    with pytest.raises(RuntimeError, match="was requested"):
        _pick_device("cuda")
    with pytest.raises(RuntimeError, match="was requested"):
        _pick_device("rocm")


def test_is_cuda_device_handles_both_branches():
    assert _is_cuda_device(torch.device("cuda")) is True
    assert _is_cuda_device(torch.device("cpu")) is False


def test_autocast_device_type_routes_amp_call():
    assert _autocast_device_type(torch.device("cpu")) == "cpu"
    if torch.cuda.is_available():
        assert _autocast_device_type(torch.device("cuda")) == "cuda"


def test_default_accuracy_gate_is_documented_value():
    assert DEFAULT_ACCURACY_GATE == 0.8
