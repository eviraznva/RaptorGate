"""Dataset registry and shared downloader utilities.

Each dataset is a self-contained plugin that lives in its own module under this
package. Plugins are registered via :func:`raptorgate_ml.datasets.registry.register`
and looked up through :func:`get_dataset` / :func:`available_datasets`. Adding
a new dataset is a single new file plus a ``@register`` call.
"""

from __future__ import annotations

import importlib
import pkgutil

import requests

from raptorgate_ml.datasets.base import (
    DatasetFile,
    DownloadKind,
    download_file,
    load_cicids_labels,
)
from raptorgate_ml.datasets.cicids2017 import HF_TRAFFIC_LABEL_FILES
from raptorgate_ml.datasets.registry import DatasetSpec, all, get, register

__all__ = [
    "DatasetFile",
    "DatasetSpec",
    "DownloadKind",
    "HF_TRAFFIC_LABEL_FILES",
    "available_datasets",
    "download_cicids2017",
    "download_file",
    "get_dataset",
    "load_cicids_labels",
    "register",
    "requests",
]


available_datasets = all
get_dataset = get


def _load_plugins() -> None:
    package = importlib.import_module("raptorgate_ml.datasets")
    for module_info in pkgutil.iter_modules(package.__path__):
        if module_info.name.startswith("_") or module_info.name in {"base", "registry"}:
            continue
        importlib.import_module(f"raptorgate_ml.datasets.{module_info.name}")


_load_plugins()


def download_cicids2017(target_dir, names=None):
    """Backward-compat shim for the original CIC-IDS-2017 downloader."""
    return get_dataset("cicids2017").download(target_dir, names)
