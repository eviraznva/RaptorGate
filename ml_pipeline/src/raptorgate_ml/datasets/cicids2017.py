"""CIC-IDS-2017 dataset plugin.

Five daily PCAPs (Monday–Friday) plus a label archive that maps each
``(src_ip, dst_ip, sport, dport, proto, timestamp)`` tuple to a benign/malicious
flow label. The official CIC hosts are slow and unreliable, so we fall back to
a HuggingFace mirror of the same files; the label archive falls back from the
official ``.zip`` to a per-day Parquet mirror.
"""

from __future__ import annotations

from pathlib import Path

from raptorgate_ml.datasets import download_file
from raptorgate_ml.datasets.base import (
    HF_PCAP_BASE,
    HF_TRAFFIC_LABELS_BASE,
    OFFICIAL_BASES,
    DatasetFile,
)
from raptorgate_ml.datasets.registry import register
from raptorgate_ml.labeling import FlowLabelIndex


HF_TRAFFIC_LABEL_FILES: tuple[str, ...] = (
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet",
    "Monday-WorkingHours.pcap_ISCX.csv.parquet",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet",
    "Tuesday-WorkingHours.pcap_ISCX.csv.parquet",
    "Wednesday-workingHours.pcap_ISCX.csv.parquet",
)


def _pcap_urls(*remote_names: str) -> tuple[str, ...]:
    urls: list[str] = []
    for remote_name in remote_names:
        urls.append(f"{HF_PCAP_BASE}/{remote_name}?download=true")
        urls.extend(f"{base}/PCAPs/{remote_name}" for base in OFFICIAL_BASES)
    return tuple(dict.fromkeys(urls))


def _zip_urls(*remote_names: str) -> tuple[str, ...]:
    urls: list[str] = []
    for remote_name in remote_names:
        urls.extend(f"{base}/{remote_name}" for base in OFFICIAL_BASES)
        urls.extend(f"{base}/CSVs/{remote_name}" for base in OFFICIAL_BASES)
    return tuple(dict.fromkeys(urls))


CICIDS2017_FILES: tuple[DatasetFile, ...] = (
    DatasetFile("Monday-WorkingHours.pcap", "pcap", _pcap_urls("Monday-WorkingHours.pcap")),
    DatasetFile("Tuesday-WorkingHours.pcap", "pcap", _pcap_urls("Tuesday-WorkingHours.pcap")),
    DatasetFile(
        "Wednesday-WorkingHours.pcap",
        "pcap",
        _pcap_urls("Wednesday-WorkingHours.pcap", "Wednesday-workingHours.pcap"),
    ),
    DatasetFile("Thursday-WorkingHours.pcap", "pcap", _pcap_urls("Thursday-WorkingHours.pcap")),
    DatasetFile("Friday-WorkingHours.pcap", "pcap", _pcap_urls("Friday-WorkingHours.pcap")),
    DatasetFile("GeneratedLabelledFlows.zip", "zip", _zip_urls("GeneratedLabelledFlows.zip")),
)


def _download_generated_labelled_flows(target_dir: Path) -> Path:
    zip_target = target_dir / "GeneratedLabelledFlows.zip"
    try:
        download_file(_zip_urls("GeneratedLabelledFlows.zip"), zip_target, "zip")
        return zip_target
    except RuntimeError:
        parquet_dir = target_dir / "GeneratedLabelledFlows"
        parquet_dir.mkdir(parents=True, exist_ok=True)
        for name in HF_TRAFFIC_LABEL_FILES:
            download_file(
                (f"{HF_TRAFFIC_LABELS_BASE}/{name}?download=true",),
                parquet_dir / name,
                "parquet",
            )
        return parquet_dir


@register
class CicIds2017:
    name = "cicids2017"
    description = "CIC-IDS-2017: 5 daily PCAPs + per-flow labels (~50 GB on disk)"

    def download(
        self, target_dir: Path, names: list[str] | None = None
    ) -> list[Path]:
        out: list[Path] = []
        for entry in CICIDS2017_FILES:
            if names and entry.name not in names:
                continue
            if entry.name == "GeneratedLabelledFlows.zip":
                out.append(_download_generated_labelled_flows(target_dir))
                continue
            dst = target_dir / entry.name
            download_file(entry.urls, dst, entry.kind)
            out.append(dst)
        return out

    def label_paths(self, target_dir: Path) -> list[Path]:
        labels_dir = target_dir / "GeneratedLabelledFlows"
        zip_path = target_dir / "GeneratedLabelledFlows.zip"
        if labels_dir.is_dir():
            return sorted(labels_dir.rglob("*.parquet")) + sorted(labels_dir.rglob("*.csv"))
        if zip_path.exists():
            return [zip_path]
        return []

    def load_label_index(self, paths: list[Path]) -> FlowLabelIndex:
        return FlowLabelIndex.from_cicids_files(paths)
