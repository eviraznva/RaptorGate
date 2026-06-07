from datetime import datetime
from pathlib import Path

import polars as pl
import pytest

from raptorgate_ml import datasets
from raptorgate_ml.labeling import FlowLabelIndex


def test_registry_contains_expected_datasets():
    names = [s.name for s in datasets.available_datasets()]
    assert "cicids2017" in names
    assert "cicids2018" in names
    assert "unsw_nb15" in names


def test_get_dataset_unknown_raises_with_listing():
    with pytest.raises(ValueError, match="cicids2017"):
        datasets.get_dataset("does-not-exist")


def test_cicids2018_label_paths_finds_label_csv(tmp_path: Path):
    label_csv = tmp_path / "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    label_csv.write_text("Source IP,Destination IP,Source Port,Destination Port,Protocol,Label\n")
    spec = datasets.get_dataset("cicids2018")
    assert spec.label_paths(tmp_path) == [label_csv]


def test_cicids2018_load_label_index_reuses_cic_format(tmp_path: Path):
    label_csv = tmp_path / "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    pl.DataFrame(
        {
            "Source IP": ["10.0.0.1"],
            "Destination IP": ["8.8.8.8"],
            "Source Port": [51000],
            "Destination Port": [443],
            "Protocol": [6],
            "Label": ["BENIGN"],
        }
    ).write_csv(label_csv)
    spec = datasets.get_dataset("cicids2018")
    idx = spec.load_label_index([label_csv])
    assert len(idx) == 1


def test_unsw_nb15_download_raises_clear_error(tmp_path: Path):
    spec = datasets.get_dataset("unsw_nb15")
    with pytest.raises(NotImplementedError, match="not publicly downloadable"):
        spec.download(tmp_path)


def test_unsw_nb15_label_index_uses_dataframe_factory(tmp_path: Path):
    label_csv = tmp_path / "UNSW_NB15_training-set.csv"
    pl.DataFrame(
        {
            "srcip": ["10.0.0.1", "10.0.0.2"],
            "dstip": ["8.8.8.8", "1.1.1.1"],
            "sport": [51000, 51001],
            "dsport": [443, 80],
            "proto": [6, 6],
            "label": [0, 1],
            "attack_cat": ["Normal", "DoS"],
        }
    ).write_csv(label_csv)
    spec = datasets.get_dataset("unsw_nb15")
    idx = spec.load_label_index([label_csv])
    assert len(idx) == 2
    match_benign = idx.match_for(
        _tup("10.0.0.1", "8.8.8.8", 51000, 443, 6)
    )
    match_dos = idx.match_for(
        _tup("10.0.0.2", "1.1.1.1", 51001, 80, 6)
    )
    assert match_benign.label == "benign"
    assert match_dos.label == "malicious"


def _tup(src_ip, dst_ip, sport, dport, proto):
    from raptorgate_ml.labeling import FiveTuple

    return FiveTuple(src_ip, dst_ip, sport, dport, proto)
