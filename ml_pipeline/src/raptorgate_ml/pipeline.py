from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from multiprocessing import get_context
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import polars as pl

from raptorgate_ml import dpi as dpi_mod
from raptorgate_ml.feature_vector import FIELD_NAMES, MlFeatureVector
from raptorgate_ml.flow_stats import FlowStatsAggregator
from raptorgate_ml.labeling import FiveTuple, FlowLabelIndex, flow_id_for, label_distribution
from raptorgate_ml.pcap_reader import (
    ack_bit,
    fin_bit,
    has,
    is_syn,
    iter_packets,
    psh_bit,
    rst_bit,
    syn_bit,
)


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


@dataclass
class _PartResult:
    train_path: Path
    train_rows: int
    train_class_counts: dict[str, int]
    train_label_match_counts: dict[str, int]
    train_attack_counts: dict[str, int]
    test_path: Path | None = None
    test_rows: int | None = None
    test_class_counts: dict[str, int] | None = None
    test_label_match_counts: dict[str, int] | None = None
    test_attack_counts: dict[str, int] | None = None


_TRAINING_SCHEMA = (
    {c: pl.Float32 for c in FIELD_NAMES}
    | {
        "label": pl.String,
        "attack_label": pl.String,
        "label_matched": pl.Boolean,
        "flow_id": pl.UInt64,
        "source_file": pl.String,
    }
)


def _pkt_to_features(
    pkt,
    agg: FlowStatsAggregator,
    seen_flows: set,
) -> MlFeatureVector:
    fv = MlFeatureVector()
    fv.init_from_packet(
        ip_version=pkt.ip_version,
        ip_proto=pkt.ip_proto,
        ttl=pkt.ttl,
        src_port=pkt.src_port,
        dst_port=pkt.dst_port,
        payload_len=pkt.payload_len,
        arrival_ts=pkt.ts,
    )

    if pkt.tcp_flags is not None:
        fv.set_from_tcp(
            syn=has(pkt.tcp_flags, syn_bit()),
            ack=has(pkt.tcp_flags, ack_bit()),
            fin=has(pkt.tcp_flags, fin_bit()),
            rst=has(pkt.tcp_flags, rst_bit()),
            psh=has(pkt.tcp_flags, psh_bit()),
            window=pkt.tcp_window or 0,
        )

    ctx = dpi_mod.inspect(
        pkt.payload,
        pkt.src_port,
        pkt.dst_port,
        udp=(pkt.ip_proto == 17),
    )
    fv.set_from_dpi(ctx)

    flow_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.ip_proto)
    is_new_flow = flow_key not in seen_flows
    if is_new_flow:
        seen_flows.add(flow_key)

    iat_seconds = agg.iat_since_last(pkt.src_ip, pkt.ts)
    agg.observe_packet(
        src=pkt.src_ip,
        dst=pkt.dst_ip,
        is_syn=is_syn(pkt.tcp_flags),
        is_new_flow=is_new_flow,
        now=pkt.ts,
    )
    if ctx.app_proto == 3 and ctx.dns_answer_count >= 0 and pkt.payload_len > 0:
        agg.observe_dns_response(pkt.src_ip, ctx.dns_rcode, pkt.ts)

    snap = agg.snapshot(pkt.src_ip, pkt.ts)
    fv.set_flow_snapshot(snap, iat_seconds)
    return fv


def build_training_rows(
    pcap_paths: list[Path],
    label_index: FlowLabelIndex,
    window_secs: float = 60.0,
    include_unmatched: bool = False,
) -> pl.DataFrame:
    agg = FlowStatsAggregator(window_secs=window_secs)
    seen_flows: set = set()

    feature_rows: list[np.ndarray] = []
    labels: list[str] = []
    attack_labels: list[str] = []
    label_matched: list[bool] = []
    flow_ids: list[int] = []
    source_files: list[str] = []

    for pcap in pcap_paths:
        for pkt in iter_packets(pcap):
            fv = _pkt_to_features(pkt, agg, seen_flows)
            tup = FiveTuple(
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                proto=pkt.ip_proto,
            )
            match = label_index.match_for(tup, pkt.ts)
            if not include_unmatched and not match.matched:
                continue
            feature_rows.append(fv.to_array())
            labels.append(match.label)
            attack_labels.append(match.attack_label)
            label_matched.append(match.matched)
            flow_ids.append(flow_id_for(tup))
            source_files.append(pcap.name)

    if not feature_rows:
        return pl.DataFrame(schema=_TRAINING_SCHEMA)

    mat = np.stack(feature_rows, axis=0)
    data = {name: mat[:, i].astype(np.float32) for i, name in enumerate(FIELD_NAMES)}
    data["label"] = labels
    data["attack_label"] = attack_labels
    data["label_matched"] = label_matched
    data["flow_id"] = np.array(flow_ids, dtype=np.uint64)
    data["source_file"] = source_files
    return pl.DataFrame(data)


def write_parquet(df: pl.DataFrame, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.write_parquet(out_path, compression="zstd")


def _empty_training_frame() -> pl.DataFrame:
    return pl.DataFrame(schema=_TRAINING_SCHEMA)


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


def _value_distribution(df: pl.DataFrame, column: str) -> dict[str, int]:
    if column not in df.columns or df.is_empty():
        return {}
    counts = df.group_by(column).len().sort(column)
    return {str(row[column]): int(row["len"]) for row in counts.iter_rows(named=True)}


def _merge_parquet_parts(part_paths: list[Path], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not part_paths:
        write_parquet(_empty_training_frame(), out_path)
        return
    pl.scan_parquet([str(path) for path in part_paths]).sink_parquet(
        out_path,
        compression="zstd",
    )


def _build_part(
    pcap: Path,
    label_index: FlowLabelIndex,
    out_dir: Path,
    part_index: int,
    window_secs: float,
    test_ratio: float | None,
    seed: int,
    include_unmatched: bool,
) -> _PartResult:
    df = build_training_rows(
        [pcap],
        label_index,
        window_secs=window_secs,
        include_unmatched=include_unmatched,
    )

    if test_ratio is None:
        train_path = out_dir / f"part-{part_index:04d}-train.parquet"
        write_parquet(df, train_path)
        return _PartResult(
            train_path=train_path,
            train_rows=df.height,
            train_class_counts=label_distribution(df),
            train_label_match_counts=_bool_distribution(df, "label_matched"),
            train_attack_counts=_value_distribution(df, "attack_label"),
        )

    train_df, test_df = _split_train_test(df, test_ratio, seed)
    train_path = out_dir / f"part-{part_index:04d}-train.parquet"
    test_path = out_dir / f"part-{part_index:04d}-test.parquet"
    write_parquet(train_df, train_path)
    write_parquet(test_df, test_path)
    return _PartResult(
        train_path=train_path,
        train_rows=train_df.height,
        train_class_counts=label_distribution(train_df),
        train_label_match_counts=_bool_distribution(train_df, "label_matched"),
        train_attack_counts=_value_distribution(train_df, "attack_label"),
        test_path=test_path,
        test_rows=test_df.height,
        test_class_counts=label_distribution(test_df),
        test_label_match_counts=_bool_distribution(test_df, "label_matched"),
        test_attack_counts=_value_distribution(test_df, "attack_label"),
    )


def _build_parts(
    pcap_paths: list[Path],
    label_index: FlowLabelIndex,
    out_dir: Path,
    window_secs: float,
    test_ratio: float | None,
    seed: int,
    jobs: int,
    include_unmatched: bool,
) -> list[_PartResult]:
    if jobs <= 1 or len(pcap_paths) <= 1:
        return [
            _build_part(
                pcap,
                label_index,
                out_dir,
                part_index,
                window_secs,
                test_ratio,
                seed,
                include_unmatched,
            )
            for part_index, pcap in enumerate(pcap_paths)
        ]

    results: list[_PartResult] = []
    with ProcessPoolExecutor(max_workers=jobs, mp_context=get_context("spawn")) as pool:
        futures = [
            pool.submit(
                _build_part,
                pcap,
                label_index,
                out_dir,
                part_index,
                window_secs,
                test_ratio,
                seed,
                include_unmatched,
            )
            for part_index, pcap in enumerate(pcap_paths)
        ]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda result: result.train_path.name)


def run_build(
    pcap_paths: list[Path],
    label_index: FlowLabelIndex,
    out_path: Path,
    window_secs: float = 60.0,
    test_out_path: Path | None = None,
    test_ratio: float = 0.2,
    seed: int = 42,
    jobs: int = 1,
    include_unmatched: bool = False,
) -> BuildResult:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="raptorgate-ml-build-", dir=out_path.parent) as tmp:
        part_results = _build_parts(
            pcap_paths,
            label_index,
            Path(tmp),
            window_secs,
            test_ratio if test_out_path is not None else None,
            seed,
            jobs,
            include_unmatched,
        )
        _merge_parquet_parts([result.train_path for result in part_results], out_path)

        test_rows = None
        test_class_counts = None
        test_label_match_counts = None
        test_attack_counts = None
        if test_out_path is not None:
            _merge_parquet_parts(
                [result.test_path for result in part_results if result.test_path is not None],
                test_out_path,
            )
            test_rows = sum(result.test_rows or 0 for result in part_results)
            test_class_counts = _merge_counts(
                [result.test_class_counts or {} for result in part_results]
            )
            test_label_match_counts = _merge_counts(
                [result.test_label_match_counts or {} for result in part_results]
            )
            test_attack_counts = _merge_counts(
                [result.test_attack_counts or {} for result in part_results]
            )

    return BuildResult(
        rows=sum(result.train_rows for result in part_results),
        class_counts=_merge_counts([result.train_class_counts for result in part_results]),
        out_path=out_path,
        label_match_counts=_merge_counts(
            [result.train_label_match_counts for result in part_results]
        ),
        attack_counts=_merge_counts([result.train_attack_counts for result in part_results]),
        test_rows=test_rows,
        test_class_counts=test_class_counts,
        test_label_match_counts=test_label_match_counts,
        test_attack_counts=test_attack_counts,
        test_out_path=test_out_path,
    )
