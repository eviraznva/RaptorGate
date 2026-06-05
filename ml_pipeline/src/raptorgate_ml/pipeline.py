from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import numpy as np
import polars as pl
import pyarrow as pa

from raptorgate_ml.feature_names import FIELD_NAMES

BENIGN = "benign"
MALICIOUS = "malicious"
RAYON_THREADS_ENV = "RAPTORGATE_PCAP_RAYON_THREADS"

_PIPE_DEBUG = os.environ.get("RAPTORGATE_PIPELINE_DEBUG") == "1"


def _dbg(msg: str) -> None:
    if _PIPE_DEBUG:
        print(f"[rg-ml-pipe] {msg}", flush=True)


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
    _dbg("_empty_training_frame: returning schema-only frame (no rows survived filter)")
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

    _dbg(
        f"_build_one: enter pcap={pcap_path!r} table_rows={table.num_rows} "
        f"attack_names={len(attack_names)} window_secs={window_secs} num_workers={num_workers}"
    )
    idx = LabelIndex()
    idx.absorb_arrow(table)
    _dbg(
        f"_build_one: idx after absorb_arrow len={len(idx)} "
        f"source_rows={idx.source_rows} indexed_rows={idx.indexed_rows} "
        f"timed_rows={idx.timed_rows} null_labels={idx.null_labels} "
        f"invalid_rows={idx.invalid_rows}"
    )
    out = _bf(_P(pcap_path), idx, window_secs=window_secs, num_workers=num_workers)
    n = out.n_rows
    _dbg(f"_build_one: build_features_py returned n_rows={n}")

    features = np.frombuffer(out.features_bytes, dtype=np.float32).reshape(n, 38).copy()
    label_arr = np.frombuffer(out.label, dtype=np.uint8).copy()
    attack_idx_arr = np.frombuffer(out.attack_idx_bytes, dtype=np.int32).copy()
    flow_id_arr = np.frombuffer(out.flow_id_bytes, dtype=np.uint64).copy()

    matched_raw = out.matched
    matched_list_type = type(matched_raw).__name__
    matched_py = np.asarray(matched_raw, dtype=bool)
    matched_sum = int(matched_py.sum()) if matched_py.size else 0
    matched_head = matched_py[:8].tolist() if matched_py.size else []
    matched_tail = matched_py[-8:].tolist() if matched_py.size else []
    attack_idx_pos = int((attack_idx_arr > 0).sum())
    label_ones = int(label_arr.sum())
    _dbg(
        f"_build_one: features shape={features.shape} "
        f"label sum(label==1)={label_ones}/{n} "
        f"attack_idx>0 count={attack_idx_pos}/{n} "
        f"matched raw_type={matched_list_type} len={len(matched_raw)} "
        f"np.asarray(dtype=bool).sum={matched_sum} head={matched_head} tail={matched_tail}"
    )
    if matched_sum == 0 and n > 0:
        _dbg(
            "_build_one: WARNING every row has matched=False from Rust side; "
            "filtering in _combine will drop everything"
        )

    return _PartResult(
        features=features,
        label=label_arr,
        attack_idx=attack_idx_arr,
        matched=matched_py,
        flow_id=flow_id_arr,
        source_file=_P(pcap_path).name,
        n_rows=n,
    )


def _combine(
    parts: Sequence[_PartResult],
    attack_names: list[str],
    include_unmatched: bool,
) -> pl.DataFrame:
    _dbg(
        f"_combine: enter parts={len(parts)} include_unmatched={include_unmatched} "
        f"attack_names={len(attack_names)}"
    )
    if not parts:
        return _empty_training_frame()

    feats: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    attack_idx_parts: list[np.ndarray] = []
    matched_parts: list[np.ndarray] = []
    flow_ids: list[np.ndarray] = []
    sources: list[np.ndarray] = []

    for i, p in enumerate(parts):
        mask = np.ones(p.n_rows, dtype=bool) if include_unmatched else p.matched
        mask_sum = int(mask.sum()) if mask.size else 0
        mask_dtype = str(mask.dtype)
        _dbg(
            f"_combine: part[{i}] src={p.source_file!r} n_rows={p.n_rows} "
            f"mask dtype={mask_dtype} sum={mask_sum} "
            f"matched.sum={int(p.matched.sum())} matched.dtype={p.matched.dtype}"
        )
        if not mask.any():
            continue
        feats.append(p.features[mask])
        labels.append(p.label[mask])
        attack_idx_parts.append(p.attack_idx[mask])
        matched_parts.append(p.matched[mask])
        flow_ids.append(p.flow_id[mask])
        sources.append(np.full(int(mask.sum()), p.source_file, dtype=object))

    if not feats:
        _dbg("_combine: no part contributed any row after mask; returning empty frame")
        return _empty_training_frame()

    _dbg(f"_combine: {len(feats)} part(s) contributed rows, concatenating")

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
    df = pl.DataFrame(data, schema=_schema())
    _dbg(f"_combine: built polars DataFrame height={df.height} width={df.width}")
    return df


def _write_parquet(df: pl.DataFrame, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _dbg(f"_write_parquet: writing height={df.height} width={df.width} path={out_path}")
    df.write_parquet(out_path, compression="zstd")
    _dbg(f"_write_parquet: wrote {out_path}")


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
    _dbg(
        f"_split_train_test: enter height={df.height} test_ratio={test_ratio} seed={seed} "
        f"cols={df.columns}"
    )
    if df.is_empty():
        _dbg("_split_train_test: empty input, returning (empty, empty)")
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
    train_df = df.filter(~test_mask)
    test_df = df.filter(test_mask)
    _dbg(
        f"_split_train_test: split done train_height={train_df.height} test_height={test_df.height}"
    )
    return train_df, test_df


def _split_train_test_by_stratum(
    df: pl.DataFrame,
    test_ratio: float,
    seed: int,
    split_col: str,
    stratum_col: str,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    _dbg(
        f"_split_train_test_by_stratum: enter height={df.height} split_col={split_col} "
        f"stratum_col={stratum_col} test_ratio={test_ratio}"
    )
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
    train_df = df.filter(~test_mask)
    test_df = df.filter(test_mask)
    _dbg(
        f"_split_train_test_by_stratum: split done train_height={train_df.height} "
        f"test_height={test_df.height}"
    )
    return train_df, test_df


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
    _dbg(
        f"run_build: enter pcaps={len(pcap_list)} window_secs={window_secs} "
        f"include_unmatched={include_unmatched} test_out_path={test_out_path} "
        f"label_table_rows={label_table.num_rows} label_index_len={len(label_index)} "
        f"label_index_timed_rows={label_index.timed_rows} label_index_indexed_rows={label_index.indexed_rows}"
    )
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
    _dbg(f"run_build: outer label_index.attack_names count={len(attack_names)} first={attack_names[:3]}")
    num_workers = _resolve_num_workers()
    ordered: list[tuple[Path, _PartResult]] = []

    for i, p in enumerate(pcap_list):
        _dbg(f"run_build: processing pcap[{i}]={p}")
        ordered.append(
            (p, _build_one(str(p), label_table, attack_names, window_secs, num_workers))
        )

    parts = [pr for _, pr in ordered]
    df = _combine(parts, attack_names, include_unmatched)
    _dbg(f"run_build: combined df height={df.height} width={df.width}")

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
