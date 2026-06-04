import importlib
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATE_DIR = REPO_ROOT / "crates" / "raptorgate_pcap"


def _ensure_wheel_built() -> None:
    try:
        importlib.import_module("raptorgate_pcap")
        return
    except ImportError:
        pass
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "maturin",
            "develop",
            "--release",
            "-m",
            str(CRATE_DIR / "Cargo.toml"),
        ],
        cwd=CRATE_DIR,
    )
    importlib.import_module("raptorgate_pcap")


_ensure_wheel_built()


def gpu_kernels_work() -> bool:
    try:
        import torch
    except ImportError:
        return False
    if not torch.cuda.is_available():
        return False
    try:
        a = torch.ones(2, 2, device="cuda")
        b = torch.ones(2, 2, device="cuda")
        c = a + b
        torch.cuda.synchronize()
        return bool((c == 2).all().item())
    except RuntimeError:
        return False
