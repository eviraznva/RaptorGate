import os
from pathlib import Path

import click
import polars as pl

from raptorgate_ml.datasets import download_cicids2017
from raptorgate_ml.feature_vector import FIELD_NAMES
from raptorgate_ml.labeling import FlowLabelIndex, discover_label_files, label_distribution
from raptorgate_ml.ml_model import TrainConfig, train_model
from raptorgate_ml.pipeline import run_build


def _echo_counts(title: str, counts: dict[str, int] | None, limit: int = 12) -> None:
    if not counts:
        return
    click.echo(title)
    for cls, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]:
        click.echo(f"  {cls}: {n}")


@click.group()
def main() -> None:
    """RaptorGate ML training data pipeline."""


@main.command()
@click.option("--dataset", type=click.Choice(["cicids2017"]), default="cicids2017")
@click.option("--target", type=click.Path(path_type=Path), required=True)
@click.option("--file", "files", multiple=True, help="Subset of dataset file names to fetch.")
def download(dataset: str, target: Path, files: tuple[str, ...]) -> None:
    """Download a public PCAP dataset."""
    if dataset == "cicids2017":
        paths = download_cicids2017(target, list(files) if files else None)
        for p in paths:
            click.echo(f"ok {p}")


@main.command()
@click.option("--pcap", "pcaps", multiple=True, type=click.Path(path_type=Path, exists=True))
@click.option("--pcap-dir", type=click.Path(path_type=Path, exists=True, file_okay=False))
@click.option("--labels-dir", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--out", "out_path", type=click.Path(path_type=Path), required=True)
@click.option("--test-out", "test_out_path", type=click.Path(path_type=Path))
@click.option("--test-ratio", type=click.FloatRange(0.0, 1.0, min_open=True, max_open=True), default=0.2)
@click.option("--seed", type=int, default=42)
@click.option("--jobs", type=int)
@click.option("--window", type=float, default=60.0)
@click.option("--include-unmatched", is_flag=True)
def build(
    pcaps: tuple[Path, ...],
    pcap_dir: Path | None,
    labels_dir: Path,
    out_path: Path,
    test_out_path: Path | None,
    test_ratio: float,
    seed: int,
    jobs: int | None,
    window: float,
    include_unmatched: bool,
) -> None:
    """Process PCAPs into labeled feature Parquet."""
    if pcaps and pcap_dir is not None:
        raise click.ClickException("use either --pcap or --pcap-dir, not both")
    if pcap_dir is None and not pcaps:
        raise click.ClickException("provide at least one --pcap or a --pcap-dir")

    pcap_paths = sorted(pcap_dir.glob("*.pcap")) if pcap_dir is not None else list(pcaps)
    if not pcap_paths:
        raise click.ClickException(f"no .pcap files under {pcap_dir}")

    effective_jobs = jobs
    if effective_jobs is None:
        effective_jobs = min(2, len(pcap_paths), os.cpu_count() or 1)
    if effective_jobs < 1:
        raise click.ClickException("--jobs must be at least 1")

    effective_test_out = test_out_path
    if pcap_dir is not None and effective_test_out is None:
        effective_test_out = out_path.with_name("test.parquet")

    label_files = discover_label_files(labels_dir)
    if not label_files:
        raise click.ClickException(f"no label CSV/Parquet files under {labels_dir}")
    idx = FlowLabelIndex.from_cicids_files(label_files)
    click.echo(f"label index: {len(idx)} flows from {len(label_files)} files")
    click.echo(
        "label stats: "
        f"source_rows={idx.stats.source_rows} indexed_rows={idx.stats.indexed_rows} "
        f"timed_rows={idx.stats.timed_rows} null_labels={idx.stats.null_labels} "
        f"invalid_rows={idx.stats.invalid_rows}"
    )

    result = run_build(
        pcap_paths,
        idx,
        out_path,
        window_secs=window,
        test_out_path=effective_test_out,
        test_ratio=test_ratio,
        seed=seed,
        jobs=effective_jobs,
        include_unmatched=include_unmatched,
    )
    click.echo(f"rows={result.rows} out={result.out_path}")
    _echo_counts("class balance:", result.class_counts)
    _echo_counts("label matched:", result.label_match_counts)
    _echo_counts("attack labels:", result.attack_counts)
    if result.test_out_path is not None:
        click.echo(f"test_rows={result.test_rows} out={result.test_out_path}")
        _echo_counts("test class balance:", result.test_class_counts)
        _echo_counts("test label matched:", result.test_label_match_counts)
        _echo_counts("test attack labels:", result.test_attack_counts)


@main.command()
@click.option("--train", "train_path", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--test", "test_path", type=click.Path(path_type=Path, exists=True))
@click.option("--out", "out_path", type=click.Path(path_type=Path), required=True)
@click.option("--metadata-out", "metadata_path", type=click.Path(path_type=Path))
@click.option("--epochs", type=int, default=10)
@click.option("--batch-size", type=int, default=65_536)
@click.option("--seed", type=int, default=42)
@click.option("--learning-rate", type=float, default=1e-3)
@click.option("--weight-decay", type=float, default=1e-4)
@click.option("--dropout", type=click.FloatRange(0.0, 1.0, max_open=True), default=0.15)
@click.option("--width", type=int, default=256)
@click.option("--residual-blocks", type=int, default=4)
@click.option("--loss", "loss_name", type=click.Choice(["weighted_ce", "focal"]), default="weighted_ce")
@click.option("--focal-gamma", type=float, default=2.0)
@click.option("--amp/--no-amp", default=True)
def train(
    train_path: Path,
    test_path: Path | None,
    out_path: Path,
    metadata_path: Path | None,
    epochs: int,
    batch_size: int,
    seed: int,
    learning_rate: float,
    weight_decay: float,
    dropout: float,
    width: int,
    residual_blocks: int,
    loss_name: str,
    focal_gamma: float,
    amp: bool,
) -> None:
    """Train an ONNX traffic classifier from feature Parquet."""
    if epochs < 1:
        raise click.ClickException("--epochs must be at least 1")
    if batch_size < 1:
        raise click.ClickException("--batch-size must be at least 1")
    if learning_rate <= 0.0:
        raise click.ClickException("--learning-rate must be greater than 0")
    if weight_decay < 0.0:
        raise click.ClickException("--weight-decay must be greater than or equal to 0")
    if width < 16:
        raise click.ClickException("--width must be at least 16")
    if residual_blocks < 0:
        raise click.ClickException("--residual-blocks must be greater than or equal to 0")
    if focal_gamma < 0.0:
        raise click.ClickException("--focal-gamma must be greater than or equal to 0")

    try:
        result = train_model(
            TrainConfig(
                train_path=train_path,
                test_path=test_path,
                out_path=out_path,
                metadata_path=metadata_path,
                epochs=epochs,
                batch_size=batch_size,
                seed=seed,
                learning_rate=learning_rate,
                weight_decay=weight_decay,
                dropout=dropout,
                width=width,
                residual_blocks=residual_blocks,
                loss=loss_name,
                focal_gamma=focal_gamma,
                amp=amp,
            ),
            log=click.echo,
        )
    except (RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"ok model={result.out_path}")
    click.echo(f"metadata={result.metadata_path}")
    click.echo(f"checksum={result.checksum}")


@main.command()
@click.option("--parquet", "parquet_path", type=click.Path(path_type=Path, exists=True), required=True)
def stats(parquet_path: Path) -> None:
    """Quick sanity report on a built Parquet file."""
    df = pl.read_parquet(parquet_path)
    click.echo(f"rows: {df.height}  cols: {df.width}")
    click.echo(f"class balance: {label_distribution(df)}")
    desc = df.select([c for c in FIELD_NAMES if c in df.columns]).describe()
    click.echo(str(desc))


if __name__ == "__main__":
    main()
