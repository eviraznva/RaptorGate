import bisect
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import polars as pl

from raptorgate_ml.datasets import load_cicids_labels

Label = Literal["benign", "malicious"]


@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int


@dataclass(frozen=True)
class LabelMatch:
    label: Label
    attack_label: str
    matched: bool


@dataclass(frozen=True)
class LabelIndexStats:
    source_rows: int = 0
    indexed_rows: int = 0
    null_labels: int = 0
    invalid_rows: int = 0
    timed_rows: int = 0


@dataclass(frozen=True)
class _TimedLabel:
    start_ts: float
    end_ts: float
    label: Label
    attack_label: str


@dataclass
class _TimedLabels:
    starts: list[float]
    labels: list[_TimedLabel]


def _normalize_label(raw: object) -> Label | None:
    if not raw:
        return None
    u = str(raw).strip().upper()
    if u in {"", "NULL", "NONE", "NAN"}:
        return None
    return "benign" if u == "BENIGN" else "malicious"


def _attack_label(raw: object) -> str | None:
    label = _normalize_label(raw)
    if label is None:
        return None
    text = str(raw).strip()
    return "BENIGN" if label == "benign" else text


def _reverse_tuple(tup: FiveTuple) -> FiveTuple:
    return FiveTuple(
        src_ip=tup.dst_ip,
        dst_ip=tup.src_ip,
        src_port=tup.dst_port,
        dst_port=tup.src_port,
        proto=tup.proto,
    )


def _epoch_seconds(raw: object) -> float | None:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw.replace(tzinfo=timezone.utc).timestamp()
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def flow_id_for(tup: FiveTuple) -> int:
    left = (tup.src_ip, int(tup.src_port))
    right = (tup.dst_ip, int(tup.dst_port))
    if right < left:
        left, right = right, left
    raw = f"{tup.proto}|{left[0]}|{left[1]}|{right[0]}|{right[1]}".encode()
    return int.from_bytes(hashlib.blake2b(raw, digest_size=8).digest(), "big")


class FlowLabelIndex:
    def __init__(self) -> None:
        self._by_tuple: dict[FiveTuple, Label] = {}
        self._attack_by_tuple: dict[FiveTuple, str] = {}
        self._timed_by_tuple: dict[FiveTuple, _TimedLabels] = {}
        self.stats = LabelIndexStats()

    @staticmethod
    def normalize_dataframe(df: pl.DataFrame) -> pl.DataFrame:
        """Project a per-flow DataFrame down to the columns ``absorb`` expects.

        Required output columns: ``src_ip``, ``dst_ip``, ``src_port``, ``dst_port``,
        ``proto``, ``label`` (already normalized to ``benign``/``malicious``),
        ``attack_label``. Optional: ``timestamp``, ``flow_duration_us``.
        """
        keep = [
            c
            for c in (
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "proto",
                "label",
                "attack_label",
                "timestamp",
                "flow_duration_us",
            )
            if c in df.columns
        ]
        if "label" not in keep:
            raise ValueError("DataFrame must contain a 'label' column")
        return df.select(keep)

    def absorb(self, df: pl.DataFrame) -> None:
        """Ingest a normalized DataFrame into this index. Counts roll into stats."""
        if df.is_empty():
            return
        for col in ("src_ip", "dst_ip", "src_port", "dst_port", "proto", "label"):
            if col not in df.columns:
                raise ValueError(f"normalized DataFrame missing {col!r}")

        timed: dict[FiveTuple, list[_TimedLabel]] = {}
        required = {"src_ip", "dst_ip", "src_port", "dst_port", "proto", "label"}
        optional = [c for c in ("attack_label", "timestamp", "flow_duration_us") if c in df.columns]
        selected = list(required | set(optional))
        for row in df.select(selected).iter_rows(named=True):
            self.stats = LabelIndexStats(
                source_rows=self.stats.source_rows + 1,
                indexed_rows=self.stats.indexed_rows,
                null_labels=self.stats.null_labels,
                invalid_rows=self.stats.invalid_rows,
                timed_rows=self.stats.timed_rows,
            )
            label = _normalize_label(row["label"])
            attack_label = row.get("attack_label")
            if attack_label is None or attack_label == "":
                attack_label = _attack_label(row["label"])
            if label is None or attack_label is None:
                self.stats = LabelIndexStats(
                    source_rows=self.stats.source_rows,
                    indexed_rows=self.stats.indexed_rows,
                    null_labels=self.stats.null_labels + 1,
                    invalid_rows=self.stats.invalid_rows,
                    timed_rows=self.stats.timed_rows,
                )
                continue
            try:
                tup = FiveTuple(
                    src_ip=str(row["src_ip"]),
                    dst_ip=str(row["dst_ip"]),
                    src_port=int(row["src_port"]),
                    dst_port=int(row["dst_port"]),
                    proto=int(row["proto"]),
                )
            except (TypeError, ValueError):
                self.stats = LabelIndexStats(
                    source_rows=self.stats.source_rows,
                    indexed_rows=self.stats.indexed_rows,
                    null_labels=self.stats.null_labels,
                    invalid_rows=self.stats.invalid_rows + 1,
                    timed_rows=self.stats.timed_rows,
                )
                continue
            self._by_tuple[tup] = label
            self._attack_by_tuple[tup] = str(attack_label)
            self.stats = LabelIndexStats(
                source_rows=self.stats.source_rows,
                indexed_rows=self.stats.indexed_rows + 1,
                null_labels=self.stats.null_labels,
                invalid_rows=self.stats.invalid_rows,
                timed_rows=self.stats.timed_rows,
            )

            start_ts = _epoch_seconds(row.get("timestamp"))
            if start_ts is None:
                continue
            try:
                duration_us = max(0, int(row.get("flow_duration_us") or 0))
            except (TypeError, ValueError):
                duration_us = 0
            duration_secs = duration_us / 1_000_000.0
            end_ts = start_ts + max(duration_secs, 1.0)
            timed.setdefault(tup, []).append(
                _TimedLabel(
                    start_ts=start_ts,
                    end_ts=end_ts,
                    label=label,
                    attack_label=str(attack_label),
                )
            )
            self.stats = LabelIndexStats(
                source_rows=self.stats.source_rows,
                indexed_rows=self.stats.indexed_rows,
                null_labels=self.stats.null_labels,
                invalid_rows=self.stats.invalid_rows,
                timed_rows=self.stats.timed_rows + 1,
            )

        for tup, labels in timed.items():
            ordered = sorted(labels, key=lambda item: item.start_ts)
            self._timed_by_tuple[tup] = _TimedLabels(
                starts=[item.start_ts for item in ordered],
                labels=ordered,
            )

    @classmethod
    def from_cicids_files(cls, paths: list[Path]) -> "FlowLabelIndex":
        idx = cls()
        for path in paths:
            df = load_cicids_labels(path)
            if df.is_empty():
                continue
            if "label" not in df.columns:
                idx.stats = LabelIndexStats(
                    source_rows=idx.stats.source_rows + df.height,
                    indexed_rows=idx.stats.indexed_rows,
                    null_labels=idx.stats.null_labels,
                    invalid_rows=idx.stats.invalid_rows + df.height,
                    timed_rows=idx.stats.timed_rows,
                )
                continue
            normalized = cls.normalize_dataframe(df)
            idx.absorb(normalized)
        return idx

    @classmethod
    def from_cicids_csvs(cls, csv_paths: list[Path]) -> "FlowLabelIndex":
        return cls.from_cicids_files(csv_paths)

    def __len__(self) -> int:
        return len(self._by_tuple)

    def _fallback_match(self, tup: FiveTuple) -> LabelMatch:
        if tup in self._by_tuple:
            label = self._by_tuple[tup]
            return LabelMatch(label, self._attack_by_tuple.get(tup, label.upper()), True)
        reversed_tup = _reverse_tuple(tup)
        if reversed_tup in self._by_tuple:
            label = self._by_tuple[reversed_tup]
            return LabelMatch(
                label,
                self._attack_by_tuple.get(reversed_tup, label.upper()),
                True,
            )
        return LabelMatch("benign", "unmatched", False)

    def match_for(self, tup: FiveTuple, ts: float | None = None) -> LabelMatch:
        if ts is None or not self._timed_by_tuple:
            return self._fallback_match(tup)

        for candidate in (tup, _reverse_tuple(tup)):
            timed = self._timed_by_tuple.get(candidate)
            if timed is None:
                continue
            pos = bisect.bisect_right(timed.starts, ts + 1.0)
            for i in range(pos - 1, -1, -1):
                item = timed.labels[i]
                if item.end_ts + 1.0 < ts:
                    break
                if item.start_ts - 1.0 <= ts <= item.end_ts + 1.0:
                    return LabelMatch(item.label, item.attack_label, True)
        return LabelMatch("benign", "unmatched", False)

    def label_for(self, tup: FiveTuple, ts: float | None = None) -> Label:
        return self.match_for(tup, ts).label


def discover_label_files(labels_dir: Path) -> list[Path]:
    return sorted(labels_dir.rglob("*.csv")) + sorted(labels_dir.rglob("*.parquet"))


def discover_label_csvs(labels_dir: Path) -> list[Path]:
    return discover_label_files(labels_dir)


def label_distribution(df: pl.DataFrame) -> dict[str, int]:
    if "label" not in df.columns or df.is_empty():
        return {}
    counts = df.group_by("label").len().sort("label")
    return {row["label"]: int(row["len"]) for row in counts.iter_rows(named=True)}


def build_arrow_table(paths: "list[Path]") -> "pyarrow.Table":
    """Load CICIDS-format label files and concatenate them into a single
    pyarrow.Table with the column shape that raptorgate_pcap.LabelIndex
    .absorb_arrow expects."""
    import polars as _pl
    from raptorgate_ml.datasets import load_cicids_labels
    frames: list[_pl.DataFrame] = []
    for path in paths:
        df = load_cicids_labels(path)
        if df.is_empty() or "label" not in df.columns:
            continue
        frames.append(FlowLabelIndex.normalize_dataframe(df))
    if not frames:
        raise ValueError(f"no labeled rows in {paths!r}")
    return _pl.concat(frames).to_arrow()
