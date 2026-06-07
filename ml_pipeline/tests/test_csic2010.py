from pathlib import Path
from zipfile import ZipFile

import polars as pl

from raptorgate_ml import datasets
from raptorgate_ml.labeling import build_arrow_table
from raptorgate_ml.pipeline import run_build


def test_csic2010_materializes_pcap_and_labels_for_existing_build(tmp_path: Path):
    _write_csic_zip(
        tmp_path
        / "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm.csv.zip",
        "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm.csv",
        [
            ("0", "GET", "http://localhost:8080/tienda1/index.jsp", "", "norm"),
            ("1", "POST", "http://localhost:8080/tienda1/login.jsp", "username=alice", "norm"),
        ],
    )
    _write_csic_zip(
        tmp_path
        / "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm_test.csv.zip",
        "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm_test.csv",
        [
            ("2", "GET", "http://localhost:8080/tienda1/catalogo.jsp", "", "norm"),
        ],
    )
    _write_csic_zip(
        tmp_path
        / "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_anom.csv.zip",
        "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_anom.csv",
        [
            (
                "3",
                "GET",
                "http://localhost:8080/tienda1/publico/anadir.jsp",
                "cantidad=%27%3B+DROP+TABLE+usuarios%3B",
                "anom",
            ),
        ],
    )

    spec = datasets.get_dataset("csic2010")
    paths = spec.download(tmp_path)

    pcap = tmp_path / "CSIC-2010-HTTP.pcap"
    labels = tmp_path / "GeneratedLabelledFlows" / "CSIC-2010-HTTP.parquet"
    assert pcap in paths
    assert labels in paths
    assert pcap.exists()
    assert labels.exists()
    assert spec.label_paths(tmp_path) == [labels]

    label_df = pl.read_parquet(labels)
    assert label_df["Label"].to_list() == [
        "BENIGN",
        "BENIGN",
        "BENIGN",
        "CSIC_HTTP_ANOMALY",
    ]
    assert set(label_df["Destination Port"].to_list()) == {80}

    from raptorgate_pcap import LabelIndex

    table = build_arrow_table([labels])
    idx = LabelIndex()
    idx.absorb_arrow(table)
    out = tmp_path / "train.parquet"
    result = run_build([pcap], idx, table, out, include_unmatched=True)
    df = pl.read_parquet(out)
    assert result.rows == 4
    assert set(df["label"].to_list()) == {"benign", "malicious"}
    assert set(df["attack_label"].to_list()) == {"BENIGN", "CSIC_HTTP_ANOMALY"}
    assert df["label_matched"].to_list() == [True, True, True, True]


def _write_csic_zip(
    path: Path,
    csv_name: str,
    rows: list[tuple[str, str, str, str, str]],
) -> None:
    header = (
        '"index","method","url","protocol","userAgent","pragma","cacheControl","accept",'
        '"acceptEncoding","acceptCharset","acceptLanguage","host","connection","contentLength",'
        '"contentType","cookie","payload","label"\n'
    )
    body = "".join(
        (
            f'"{index}","{method}","{url}","HTTP/1.1","pytest-agent","no-cache",'
            f'"no-cache","*/*","gzip","utf-8","en","localhost:8080","close",'
            f'"null","application/x-www-form-urlencoded","JSESSIONID=test","{payload}","{label}"\n'
        )
        for index, method, url, payload, label in rows
    )
    with ZipFile(path, "w") as zf:
        zf.writestr(csv_name, header + body)
