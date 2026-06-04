from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from multiprocessing import get_context
from pathlib import Path
from typing import Sequence

import numpy as np
import polars as pl
import pyarrow as pa

from raptorgate_ml.feature_names import FIELD_NAMES

BENIGN = "benign"
MALICIOUS = "malicious"
RAYON_THREADS_ENV = "RAPTORGATE_PCAP_RAYON_THREADS"


@dataclass
class BuildResult:
    rows: int
    class_counts: dict[str, int]
    out_path: Path
    label_match_counts: dict[str, int] | None = None
    attack_counts: dict[str, int] | None = None
    test_rows: int | None = None
    test_class_counts: dict[str, int] | None = None
    test_label_match_counts: dict[str, int] | None = None
    test_attack_counts: dict[str, int] | None = None
    test_out_path: Path | None = None


def _schema() -> dict:
    return (
        {c: pl.Float32 for c in FIELD_NAMES}
        | {
            "label": pl.String,
            "attack_label": pl.String,
            "label_matched": pl.Boolean,
            "flow_id": pl.UInt64,
            "source_file": pl.String,
        }
    )


def _empty_training_frame() -> pl.DataFrame:
    return pl.DataFrame(schema=_schema())


@dataclass
class _PartResult:
    features: np.ndarray
    label: np.ndarray
    attack_idx: np.ndarray
    matched: np.ndarray
    flow_id: np.ndarray
    source_file: str
    n_rows: int


def _build_one(
    pcap_path: str,
    table: pa.Table,
    attack_names: list[str],
    window_secs: float,
    num_workers: int | None,
) -> _PartResult:
    from pathlib import Path as _P
    from raptorgate_pcap import LabelIndex, build_features_py as _bf

    idx = LabelIndex()
    idx.absorb_arrow(table)
    out = _bf(_P(pcap_path), idx, window_secs=window_secs, num_workers=num_workers)
    n = out.n_rows
    features = np.asarray(out.features, dtype=np.float32).reshape(n, 38)
    return _PartResult(
        features=features,
        label=np.frombuffer(out.label, dtype=np.uint8).copy(),
        attack_idx=np.asarray(out.attack_idx, dtype=np.int32),
        matched=np.asarray(out.matched, dtype=bool),
        flow_id=np.asarray(out.flow_id, dtype=np.uint64),
        source_file=_P(pcap_path).name,
        n_rows=n,
    )


def _combine(
    parts: Sequence[_PartResult],
    attack_names: list[str],
    include_unmatched: bool,
) -> pl.DataFrame:
    if not parts:
        return _empty_training_frame()

    feats: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    attack_idx_parts: list[np.ndarray] = []
    matched_parts: list[np.ndarray] = []
    flow_ids: list[np.ndarray] = []
    sources: list[np.ndarray] = []

    for p in parts:
        mask = np.ones(p.n_rows, dtype=bool) if include_unmatched else p.matched
        if not mask.any():
            continue
        feats.append(p.features[mask])
        labels.append(p.label[mask])
        attack_idx_parts.append(p.attack_idx[mask])
        matched_parts.append(p.matched[mask])
        flow_ids.append(p.flow_id[mask])
        sources.append(np.full(int(mask.sum()), p.source_file, dtype=object))

    if not feats:
        return _empty_training_frame()

    feat = np.concatenate(feats, axis=0)
    lbl = np.concatenate(labels)
    aidx = np.concatenate(attack_idx_parts)
    mtc = np.concatenate(matched_parts)
    fid = np.concatenate(flow_ids)
    src = np.concatenate(sources)
    attack_label = np.array(
        [attack_names[i] if 0 <= i < len(attack_names) else "unmatched" for i in aidx],
        dtype=object,
    )
    label_str = np.where(lbl == 1, MALICIOUS, BENIGN).astype(object)

    data: dict[str, object] = {
        name: feat[:, i].astype(np.float32, copy=False) for i, name in enumerate(FIELD_NAMES)
    }
    data.update(
        {
            "label": label_str,
            "attack_label": attack_label,
            "label_matched": mtc,
            "flow_id": fid,
            "source_file": src,
        }
    )
    return pl.DataFrame(data, schema=_schema())


def _write_parquet(df: pl.DataFrame, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.write_parquet(out_path, compression="zstd")


def _resolve_num_workers() -> int | None:
    raw = os.environ.get(RAYON_THREADS_ENV)
    if not raw or not raw.isdigit():
        return None
    n = int(raw)
    return n if n > 0 else None


def _split_train_test(
    df: pl.DataFrame,
    test_ratio: float,
    seed: int,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    if df.is_empty():
        return df, df

    split_col = "flow_id" if "flow_id" in df.columns else None
    if split_col is not None and "attack_label" in df.columns:
        return _split_train_test_by_stratum(df, test_ratio, seed, split_col, "attack_label")

    split_count = row_count = df.height
    split_values = np.arange(row_count, dtype=np.uint64)
    row_values = split_values

    if split_col is not None:
        row_values = df[split_col].to_numpy(allow_copy=True).astype(np.uint64, copy=False)
        split_values = np.unique(row_values)
        split_count = len(split_values)

    test_count = int(round(split_count * test_ratio))
    if split_count > 1 and test_ratio > 0.0:
        test_count = max(1, test_count)
    if split_count > 1:
        test_count = min(split_count - 1, test_count)

    mask = np.zeros(row_count, dtype=bool)
    if test_count > 0:
        scores = _split_scores(split_values, seed)
        test_values = split_values[np.argsort(scores, kind="stable")[:test_count]]
        mask = np.isin(row_values, test_values)

    test_mask = pl.Series(mask)
    return df.filter(~test_mask), df.filter(test_mask)


def _split_train_test_by_stratum(
    df: pl.DataFrame,
    test_ratio: float,
    seed: int,
    split_col: str,
    stratum_col: str,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    flow_strata = df.group_by(split_col).agg(pl.col(stratum_col).first())
    row_values = df[split_col].to_numpy(allow_copy=True).astype(np.uint64, copy=False)
    test_parts: list[np.ndarray] = []

    for stratum in flow_strata[stratum_col].unique().to_list():
        values = (
            flow_strata.filter(pl.col(stratum_col) == stratum)[split_col]
            .to_numpy(allow_copy=True)
            .astype(np.uint64, copy=False)
        )
        if len(values) <= 1:
            continue
        test_count = int(round(len(values) * test_ratio))
        if test_ratio > 0.0:
            test_count = max(1, test_count)
        test_count = min(len(values) - 1, test_count)
        if test_count <= 0:
            continue
        scores = _split_scores(values, seed)
        test_parts.append(values[np.argsort(scores, kind="stable")[:test_count]])

    if not test_parts:
        return df, df.clear()

    test_values = np.concatenate(test_parts)
    test_mask = pl.Series(np.isin(row_values, test_values))
    return df.filter(~test_mask), df.filter(test_mask)


def _split_scores(values: np.ndarray, seed: int) -> np.ndarray:
    x = values.astype(np.uint64, copy=True)
    x ^= np.uint64(seed)
    x ^= x >> np.uint64(30)
    x *= np.uint64(0xBF58476D1CE4E5B9)
    x ^= x >> np.uint64(27)
    x *= np.uint64(0x94D049BB133111EB)
    x ^= x >> np.uint64(31)
    return x


def _merge_counts(results: list[dict[str, int]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        for cls, value in result.items():
            counts[cls] = counts.get(cls, 0) + value
    return dict(sorted(counts.items()))


def _bool_distribution(df: pl.DataFrame, column: str) -> dict[str, int]:
    if column not in df.columns or df.is_empty():
        return {}
    counts = df.group_by(column).len().sort(column)
    return {str(row[column]).lower(): int(row["len"]) for row in counts.iter_rows(named=True)}


def _distribution(df: pl.DataFrame, column: str) -> dict[str, int]:
    if column not in df.columns or df.is_empty():
        return {}
    counts = df.group_by(column).len().sort(column)
    return {str(row[column]): int(row["len"]) for row in counts.iter_rows(named=True)}


def run_build(
    pcap_paths: Sequence[Path],
    label_index,  # raptorgate_pcap.LabelIndex
    label_table: pa.Table,  # pyarrow.Table
    out_path: Path,
    *,
    window_secs: float = 60.0,
    test_out_path: Path | None = None,
    test_ratio: float = 0.2,
    seed: int = 42,
    jobs: int = 1,
    include_unmatched: bool = False,
) -> BuildResult:
    pcap_list = [Path(p) for p in pcap_paths]
    if not pcap_list:
        _write_parquet(_empty_training_frame(), out_path)
        if test_out_path is not None:
            _write_parquet(_empty_training_frame(), test_out_path)
        return BuildResult(
            rows=0,
            class_counts={},
            out_path=out_path,
            test_out_path=test_out_path,
        )

    attack_names: list[str] = list(label_index.attack_names)
    num_workers = _resolve_num_workers()
    ordered: list[tuple[Path, _PartResult]] = []

    if jobs <= 1 or len(pcap_list) <= 1:
        for p in pcap_list:
            ordered.append(
                (p, _build_one(str(p), label_table, attack_names, window_secs, num_workers))
            )
    else:
        with ProcessPoolExecutor(max_workers=jobs, mp_context=get_context("spawn")) as pool:
            futs = {
                p: pool.submit(
                    _build_one, str(p), label_table, attack_names, window_secs, num_workers
                )
                for p in pcap_list
            }
            for p in pcap_list:
                ordered.append((p, futs[p].result()))

    parts = [pr for _, pr in ordered]
    df = _combine(parts, attack_names, include_unmatched)

    if test_out_path is not None:
        train_df, test_df = _split_train_test(df, test_ratio, seed)
        _write_parquet(train_df, out_path)
        _write_parquet(test_df, test_out_path)
        return BuildResult(
            rows=train_df.height,
            class_counts=_distribution(train_df, "label"),
            out_path=out_path,
            label_match_counts=_bool_distribution(train_df, "label_matched"),
            attack_counts=_distribution(train_df, "attack_label"),
            test_rows=test_df.height,
            test_class_counts=_distribution(test_df, "label"),
            test_label_match_counts=_bool_distribution(test_df, "label_matched"),
            test_attack_counts=_distribution(test_df, "attack_label"),
            test_out_path=test_out_path,
        )

    _write_parquet(df, out_path)
    return BuildResult(
        rows=df.height,
        class_counts=_distribution(df, "label"),
        out_path=out_path,
        label_match_counts=_bool_distribution(df, "label_matched"),
        attack_counts=_distribution(df, "attack_label"),
    )
