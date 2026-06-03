"""Registry primitives for dataset plugins.

Lives in its own module so the plugin files can import ``register`` /
``DatasetSpec`` from here without going through the parent package's
``__init__`` (which would create a circular import).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from raptorgate_ml.labeling import FlowLabelIndex


class DatasetSpec(Protocol):
    """A self-describing public PCAP attack dataset."""

    name: str
    description: str

    def download(
        self, target_dir: Path, names: list[str] | None = None
    ) -> list[Path]:
        ...

    def label_paths(self, target_dir: Path) -> list[Path]:
        ...

    def load_label_index(self, paths: list[Path]) -> "FlowLabelIndex":
        ...


_REGISTRY: dict[str, DatasetSpec] = {}


def register(spec: object) -> DatasetSpec:
    """Register a dataset plugin. Accepts either an instance or a class."""
    instance = spec() if isinstance(spec, type) else spec
    name = getattr(instance, "name", None)
    if not isinstance(name, str) or not name:
        raise ValueError("dataset plugins must set a non-empty 'name' attribute")
    if name in _REGISTRY:
        raise ValueError(f"dataset {name!r} already registered")
    _REGISTRY[name] = instance
    return instance


def get(name: str | None = None) -> DatasetSpec:
    """Look up a registered dataset by name. Falls back to the first registered."""
    if name is None:
        return all()[0]
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        names = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"unknown dataset {name!r}; available: {names}") from exc


def all() -> list[DatasetSpec]:
    """Return all registered datasets in registration order."""
    return list(_REGISTRY.values())
