from datetime import datetime
from pathlib import Path

import polars as pl

from raptorgate_ml import datasets
from raptorgate_ml.labeling import FiveTuple, FlowLabelIndex, discover_label_files


class FakeResponse:
    def __init__(self, body: bytes, content_type: str, status_code: int = 200) -> None:
        self.body = body
        self.status_code = status_code
        self.headers = {
            "content-type": content_type,
            "content-length": str(len(body)),
        }

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")

    def iter_content(self, chunk_size: int = 1 << 20):
        for i in range(0, len(self.body), chunk_size):
            yield self.body[i : i + chunk_size]


def test_download_file_resumes_from_partial_file(tmp_path: Path, monkeypatch):
    target = tmp_path / "Monday-WorkingHours.pcap"
    tmp = target.with_suffix(target.suffix + ".part")
    prefix = b"\xd4\xc3\xb2\xa1" + b"A" * 100
    tmp.write_bytes(prefix)
    remaining = b"B" * 50
    captured_headers: dict[str, str] = {}

    def fake_get(url: str, **kwargs):
        captured_headers.update(kwargs.get("headers") or {})
        return FakeResponse(
            remaining, "application/vnd.tcpdump.pcap", status_code=206
        )

    monkeypatch.setattr(datasets.requests, "get", fake_get)
    datasets.download_file(("https://example.test/file",), target, "pcap")

    assert captured_headers.get("Range") == f"bytes={len(prefix)}-"
    assert target.read_bytes() == prefix + remaining


def test_download_file_discards_partial_when_server_ignores_range(
    tmp_path: Path, monkeypatch
):
    target = tmp_path / "Monday-WorkingHours.pcap"
    tmp = target.with_suffix(target.suffix + ".part")
    tmp.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 50)
    full = b"\xd4\xc3\xb2\xa1" + b"Z" * 200

    def fake_get(url: str, **kwargs):
        return FakeResponse(full, "application/vnd.tcpdump.pcap", status_code=200)

    monkeypatch.setattr(datasets.requests, "get", fake_get)
    datasets.download_file(("https://example.test/file",), target, "pcap")

    assert target.read_bytes() == full


def test_download_file_retries_after_html_response(tmp_path: Path, monkeypatch):
    calls: list[str] = []
    html = b"<!DOCTYPE html><html><body>blocked</body></html>"
    pcap = b"\xd4\xc3\xb2\xa1" + b"\x00" * 32
    responses = {
        "https://bad.example/file": FakeResponse(html, "text/html"),
        "https://good.example/file": FakeResponse(pcap, "application/vnd.tcpdump.pcap"),
    }

    def fake_get(url: str, **kwargs):
        calls.append(url)
        return responses[url]

    monkeypatch.setattr(datasets.requests, "get", fake_get)

    target = tmp_path / "Monday-WorkingHours.pcap"
    datasets.download_file(
        ("https://bad.example/file", "https://good.example/file"),
        target,
        "pcap",
    )

    assert calls == ["https://bad.example/file", "https://good.example/file"]
    assert target.read_bytes().startswith(b"\xd4\xc3\xb2\xa1")


def test_download_file_replaces_invalid_existing_file(tmp_path: Path, monkeypatch):
    target = tmp_path / "GeneratedLabelledFlows.zip"
    target.write_text("<html>bad</html>")

    payload = b"PK\x03\x04" + b"\x00" * 32

    def fake_get(url: str, **kwargs):
        return FakeResponse(payload, "application/zip")

    monkeypatch.setattr(datasets.requests, "get", fake_get)

    datasets.download_file(("https://good.example/labels.zip",), target, "zip")

    assert target.read_bytes().startswith(b"PK\x03\x04")


def test_download_cicids2017_falls_back_to_parquet_labels(tmp_path: Path, monkeypatch):
    downloaded: list[tuple[tuple[str, ...], Path, str]] = []
    original = datasets.download_file

    def fake_download(urls: tuple[str, ...], target: Path, kind: str) -> None:
        downloaded.append((urls, target, kind))
        if target.name == "GeneratedLabelledFlows.zip":
            raise RuntimeError("zip unavailable")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "parquet": b"PAR1" + b"\x00" * 32,
        }[kind]
        target.write_bytes(payload)

    monkeypatch.setattr(datasets, "download_file", fake_download)

    paths = datasets.download_cicids2017(tmp_path, ["GeneratedLabelledFlows.zip"])

    assert paths == [tmp_path / "GeneratedLabelledFlows"]
    assert (tmp_path / "GeneratedLabelledFlows").is_dir()
    parquet_targets = [target for _, target, kind in downloaded if kind == "parquet"]
    assert len(parquet_targets) == len(datasets.HF_TRAFFIC_LABEL_FILES)
    assert all(target.suffix == ".parquet" for target in parquet_targets)

    monkeypatch.setattr(datasets, "download_file", original)


def test_parquet_labels_are_discovered_and_indexed(tmp_path: Path):
    labels_dir = tmp_path / "GeneratedLabelledFlows"
    labels_dir.mkdir()
    parquet_path = labels_dir / "Monday-WorkingHours.pcap_ISCX.csv.parquet"
    pl.DataFrame(
        {
            "Source IP": ["10.0.0.1"],
            "Destination IP": ["8.8.8.8"],
            "Source Port": [51000],
            "Destination Port": [443],
            "Protocol": [6],
            "Label": ["BENIGN"],
        }
    ).write_parquet(parquet_path)

    files = discover_label_files(labels_dir)
    idx = FlowLabelIndex.from_cicids_files(files)

    assert files == [parquet_path]
    assert len(idx) == 1
    assert idx.stats.null_labels == 0


def test_null_labels_are_not_indexed_as_malicious(tmp_path: Path):
    labels_dir = tmp_path / "GeneratedLabelledFlows"
    labels_dir.mkdir()
    parquet_path = labels_dir / "labels.parquet"
    pl.DataFrame(
        {
            "Source IP": ["10.0.0.1"],
            "Destination IP": ["8.8.8.8"],
            "Source Port": [51000],
            "Destination Port": [443],
            "Protocol": [6],
            "Timestamp": [datetime(2017, 7, 3, 11, 55, 58)],
            "Flow Duration": [1_000_000],
            "Label": [None],
        }
    ).write_parquet(parquet_path)

    idx = FlowLabelIndex.from_cicids_files([parquet_path])
    match = idx.match_for(FiveTuple("10.0.0.1", "8.8.8.8", 51000, 443, 6), 1499082958.5)

    assert len(idx) == 0
    assert idx.stats.null_labels == 1
    assert match.label == "benign"
    assert match.attack_label == "unmatched"
    assert match.matched is False


def test_timestamp_aware_labels_resolve_reused_five_tuple(tmp_path: Path):
    parquet_path = tmp_path / "labels.parquet"
    pl.DataFrame(
        {
            "Source IP": ["10.0.0.1", "10.0.0.1"],
            "Destination IP": ["8.8.8.8", "8.8.8.8"],
            "Source Port": [51000, 51000],
            "Destination Port": [443, 443],
            "Protocol": [6, 6],
            "Timestamp": [
                datetime(2017, 7, 3, 11, 55, 58),
                datetime(2017, 7, 3, 12, 0, 0),
            ],
            "Flow Duration": [2_000_000, 2_000_000],
            "Label": ["BENIGN", "DDoS"],
        }
    ).write_parquet(parquet_path)

    idx = FlowLabelIndex.from_cicids_files([parquet_path])
    tup = FiveTuple("10.0.0.1", "8.8.8.8", 51000, 443, 6)

    assert idx.match_for(tup, 1499082959.0).label == "benign"
    assert idx.match_for(tup, 1499083201.0).label == "malicious"
