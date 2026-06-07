"""CSE-CIC-IDS-2018 dataset plugin.

The 2018 corpus is a follow-up to CIC-IDS-2017 with 10 days of attack traffic
split into ~24 hourly PCAPs per day. The full set is ~400 GB, so we default to
a single day (Friday-16-02-2018) and a small subset of hourly PCAPs to stay
under the user's disk budget.

The label format is the same as CIC-IDS-2017 per-flow CSVs (5-tuple +
``Label`` column), so :meth:`FlowLabelIndex.from_cicids_files` is reused.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from raptorgate_ml.datasets import download_file
from raptorgate_ml.datasets.registry import register
from raptorgate_ml.labeling import FlowLabelIndex


_BASE = "http://205.174.165.80/CICDataset/CSE-CIC-IDS-2018/Dataset"
_LABEL_URL = f"{_BASE}/Labels"
_PCAP_BASE = f"{_BASE}/PCAPs"

DEFAULT_DAY = "Friday-16-02-2018"


@dataclass(frozen=True)
class _DaySpec:
    label_csv: str
    pcap_hours: tuple[str, ...]


DEFAULT_DAYS: dict[str, _DaySpec] = {
    "Wednesday-14-02-2018": _DaySpec(
        label_csv="Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        pcap_hours=(),
    ),
    "Thursday-15-02-2018": _DaySpec(
        label_csv="Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        pcap_hours=(),
    ),
    "Friday-16-02-2018": _DaySpec(
        label_csv="Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
        pcap_hours=(),
    ),
    "Thursday-20-02-2018": _DaySpec(
        label_csv="Thursday-20-02-2018_TrafficForML_CICFlowMeter.csv",
        pcap_hours=(),
    ),
    "Friday-23-02-2018": _DaySpec(
        label_csv="Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
        pcap_hours=(),
    ),
    "Wednesday-28-02-2018": _DaySpec(
        label_csv="Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
        pcap_hours=(),
    ),
    "Thursday-01-03-2018": _DaySpec(
        label_csv="Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
        pcap_hours=(),
    ),
    "Friday-02-03-2018": _DaySpec(
        label_csv="Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        pcap_hours=(),
    ),
}


@register
class CicIds2018:
    name = "cicids2018"
    description = (
        f"CSE-CIC-IDS-2018: 1-day subset by default ({DEFAULT_DAY}), "
        "use --file to pull more days or hourly PCAPs (~30 GB on disk)"
    )

    def download(
        self, target_dir: Path, names: list[str] | None = None
    ) -> list[Path]:
        target_dir.mkdir(parents=True, exist_ok=True)
        out: list[Path] = []
        requested = set(names) if names else {DEFAULT_DAY}

        for day_name in sorted(requested):
            spec = DEFAULT_DAYS.get(day_name)
            if spec is None:
                pcap_match = self._looks_like_hourly_pcap(day_name)
                if pcap_match is None:
                    raise ValueError(
                        f"unknown 2018 day/file {day_name!r}; "
                        f"valid days: {sorted(DEFAULT_DAYS)}"
                    )
                day, hour = pcap_match
                self._download_hourly_pcap(target_dir, day, hour)
                out.append(target_dir / f"{day}_{hour}.pcap")
                continue

            label_dst = target_dir / spec.label_csv
            download_file(
                (f"{_LABEL_URL}/{spec.label_csv}",),
                label_dst,
                "parquet" if spec.label_csv.endswith(".parquet") else "zip",
            )
            out.append(label_dst)

            for hour in spec.pcap_hours:
                self._download_hourly_pcap(target_dir, day_name, hour)
                out.append(target_dir / f"{day_name}_{hour}.pcap")

        return out

    def label_paths(self, target_dir: Path) -> list[Path]:
        return sorted(target_dir.glob("*_TrafficForML_CICFlowMeter.csv")) + sorted(
            target_dir.glob("*_TrafficForML_CICFlowMeter.csv.parquet")
        )

    def load_label_index(self, paths: list[Path]) -> FlowLabelIndex:
        return FlowLabelIndex.from_cicids_files(paths)

    @staticmethod
    def _looks_like_hourly_pcap(name: str) -> tuple[str, str] | None:
        if not name.endswith(".pcap"):
            return None
        stem = name[: -len(".pcap")]
        if "_" not in stem:
            return None
        day, _, hour = stem.rpartition("_")
        if day in DEFAULT_DAYS and hour:
            return day, hour
        return None

    @staticmethod
    def _download_hourly_pcap(target_dir: Path, day: str, hour: str) -> None:
        dst = target_dir / f"{day}_{hour}.pcap"
        url = f"{_PCAP_BASE}/{day}/{day}_{hour}.pcap"
        download_file((url,), dst, "pcap")
