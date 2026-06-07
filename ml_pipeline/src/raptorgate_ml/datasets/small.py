"""Small debug dataset — 250K packets of Friday-WorkingHours.pcap.

A trimmed pcapng (~250 MB) sliced from the head of the full
``Friday-WorkingHours.pcap`` via ``examples/slice_pcapng.rs``. The label
archive is the same CIC-IDS-2017 ``GeneratedLabelledFlows/`` directory as
the full dataset (exposed via a symlink in the on-disk layout), so the
label index build exercises the real 3.1M-row path. Only the pcap side is
truncated, which is what makes the build fast.

There is no remote source for this dataset — the pcap is local-only. The
``download()`` method is therefore a verifier: it errors out with a clear
message if the file is missing rather than silently no-op'ing.
"""

from __future__ import annotations

from pathlib import Path

from raptorgate_ml.datasets.registry import register
from raptorgate_ml.labeling import FlowLabelIndex


_SMALL_PCAP = "Friday-WorkingHours-Small.pcap"
_LABELS_SUBDIR = "GeneratedLabelledFlows"


@register
class Small:
    name = "small"
    description = "Small debug pcapng (250K packets, ~250 MB) — fast smoke test."

    def download(
        self, target_dir: Path, names: list[str] | None = None
    ) -> list[Path]:
        pcap = target_dir / _SMALL_PCAP
        if not pcap.exists():
            raise RuntimeError(
                f"{pcap} not found; place it under {target_dir} manually "
                "(this dataset has no remote source)."
            )
        return [pcap]

    def label_paths(self, target_dir: Path) -> list[Path]:
        labels_dir = target_dir / _LABELS_SUBDIR
        if not labels_dir.exists():
            return []
        return sorted(labels_dir.rglob("*.parquet")) + sorted(
            labels_dir.rglob("*.csv")
        )

    def load_label_index(self, paths: list[Path]) -> FlowLabelIndex:
        return FlowLabelIndex.from_cicids_files(paths)
