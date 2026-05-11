from pathlib import Path

import polars as pl
import pytest
from click.testing import CliRunner
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap
from scapy.packet import Raw

from raptorgate_ml.cli import main
from raptorgate_ml.labeling import FiveTuple, FlowLabelIndex
from raptorgate_ml.pipeline import _split_train_test, build_training_rows, run_build


@pytest.fixture
def tiny_pcap(tmp_path: Path) -> Path:
    pkts = [
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8", ttl=64)
        / TCP(sport=51000, dport=443, flags="S", window=65535),
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8", ttl=64)
        / TCP(sport=51000, dport=443, flags="A", window=65535)
        / Raw(load=b"\x16\x03\x01\x00\x10hello"),
        Ether()
        / IP(src="10.0.0.1", dst="1.1.1.1", ttl=64)
        / UDP(sport=33333, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
    ]
    path = tmp_path / "tiny.pcap"
    wrpcap(str(path), pkts)
    return path


def _label_index() -> FlowLabelIndex:
    idx = FlowLabelIndex()
    idx._by_tuple[FiveTuple("10.0.0.1", "8.8.8.8", 51000, 443, 6)] = "malicious"
    return idx


def test_build_produces_rows_and_labels(tiny_pcap: Path):
    df = build_training_rows([tiny_pcap], _label_index())
    assert df.height == 2
    assert "label" in df.columns
    labels = set(df["label"].to_list())
    assert "malicious" in labels


def test_build_can_keep_unmatched_rows_for_diagnostics(tiny_pcap: Path):
    df = build_training_rows([tiny_pcap], _label_index(), include_unmatched=True)
    assert df.height == 3
    assert set(df["label"].to_list()) == {"malicious", "benign"}


def test_features_have_expected_columns(tiny_pcap: Path):
    df = build_training_rows([tiny_pcap], _label_index(), include_unmatched=True)
    assert df.width == 43
    assert df["proto"].dtype.__str__().startswith("Float")
    assert {"attack_label", "label_matched", "flow_id", "source_file"}.issubset(df.columns)
    assert df["label_matched"].to_list() == [True, True, False]


def test_run_build_writes_deterministic_train_test_split(tiny_pcap: Path, tmp_path: Path):
    out = tmp_path / "train.parquet"
    test_out = tmp_path / "test.parquet"

    first = run_build(
        [tiny_pcap, tiny_pcap],
        _label_index(),
        out,
        test_out_path=test_out,
        test_ratio=0.5,
        seed=7,
        jobs=1,
    )
    first_train = pl.read_parquet(out)
    first_test = pl.read_parquet(test_out)

    second = run_build(
        [tiny_pcap, tiny_pcap],
        _label_index(),
        tmp_path / "train-again.parquet",
        test_out_path=tmp_path / "test-again.parquet",
        test_ratio=0.5,
        seed=7,
        jobs=1,
    )
    second_train = pl.read_parquet(second.out_path)
    second_test = pl.read_parquet(second.test_out_path)

    assert first.rows == second.rows == first_train.height == second_train.height
    assert first.test_rows == second.test_rows == first_test.height == second_test.height
    assert set(first_train["flow_id"].to_list()).isdisjoint(set(first_test["flow_id"].to_list()))
    assert first_train.equals(second_train)
    assert first_test.equals(second_test)


def test_split_keeps_flow_id_out_of_both_train_and_test():
    df = pl.DataFrame(
        {
            "flow_id": [1, 1, 1, 2, 2, 3],
            "label": ["benign", "benign", "benign", "malicious", "malicious", "benign"],
        }
    )

    train_df, test_df = _split_train_test(df, 0.5, seed=7)

    assert set(train_df["flow_id"].to_list()).isdisjoint(set(test_df["flow_id"].to_list()))
    assert train_df.height + test_df.height == df.height


def test_split_stratifies_attack_labels_when_possible():
    df = pl.DataFrame(
        {
            "flow_id": [1, 2, 3, 4, 5, 6, 7],
            "label": ["benign", "benign", "malicious", "malicious", "malicious", "malicious", "malicious"],
            "attack_label": ["BENIGN", "BENIGN", "DDoS", "DDoS", "PortScan", "PortScan", "Heartbleed"],
        }
    )

    train_df, test_df = _split_train_test(df, 0.5, seed=7)

    assert set(train_df["flow_id"].to_list()).isdisjoint(set(test_df["flow_id"].to_list()))
    assert "Heartbleed" in train_df["attack_label"].to_list()
    assert "Heartbleed" not in test_df["attack_label"].to_list()
    for label in ("BENIGN", "DDoS", "PortScan"):
        assert label in train_df["attack_label"].to_list()
        assert label in test_df["attack_label"].to_list()


def test_build_cli_accepts_pcap_dir_and_default_test_out(tiny_pcap: Path, tmp_path: Path):
    pcaps = tmp_path / "pcaps"
    labels = tmp_path / "labels"
    pcaps.mkdir()
    labels.mkdir()
    (pcaps / "a.pcap").write_bytes(tiny_pcap.read_bytes())
    (pcaps / "b.pcap").write_bytes(tiny_pcap.read_bytes())
    pl.DataFrame(
        {
            "Source IP": ["10.0.0.1"],
            "Destination IP": ["8.8.8.8"],
            "Source Port": [51000],
            "Destination Port": [443],
            "Protocol": [6],
            "Label": ["BENIGN"],
        }
    ).write_parquet(labels / "labels.parquet")

    out = tmp_path / "features" / "train.parquet"
    result = CliRunner().invoke(
        main,
        [
            "build",
            "--pcap-dir",
            str(pcaps),
            "--labels-dir",
            str(labels),
            "--out",
            str(out),
            "--jobs",
            "1",
            "--test-ratio",
            "0.5",
        ],
    )

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert (out.parent / "test.parquet").exists()


def test_build_cli_preserves_single_output_pcap_mode(tiny_pcap: Path, tmp_path: Path):
    labels = tmp_path / "labels"
    labels.mkdir()
    pl.DataFrame(
        {
            "Source IP": ["10.0.0.1"],
            "Destination IP": ["8.8.8.8"],
            "Source Port": [51000],
            "Destination Port": [443],
            "Protocol": [6],
            "Label": ["BENIGN"],
        }
    ).write_parquet(labels / "labels.parquet")

    out = tmp_path / "train.parquet"
    result = CliRunner().invoke(
        main,
        [
            "build",
            "--pcap",
            str(tiny_pcap),
            "--labels-dir",
            str(labels),
            "--out",
            str(out),
            "--jobs",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert not (tmp_path / "test.parquet").exists()


def test_build_cli_requires_pcap_source(tmp_path: Path):
    labels = tmp_path / "labels"
    labels.mkdir()

    result = CliRunner().invoke(
        main,
        [
            "build",
            "--labels-dir",
            str(labels),
            "--out",
            str(tmp_path / "train.parquet"),
        ],
    )

    assert result.exit_code != 0
    assert "provide at least one --pcap or a --pcap-dir" in result.output
