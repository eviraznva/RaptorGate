"""CSIC 2010 HTTP dataset plugin.

The public CSIC 2010 distribution linked from Pete Scully's mirror is CSV-only.
To keep the standard RaptorGate path, this plugin materializes the request rows
as a synthetic HTTP PCAP and writes CIC-style flow labels beside it.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from io import TextIOWrapper
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import ZipFile

import polars as pl

from raptorgate_ml.datasets import download_file
from raptorgate_ml.datasets.base import DatasetFile
from raptorgate_ml.datasets.registry import register
from raptorgate_ml.labeling import FlowLabelIndex


_BASE = "http://lexr.ai/csic_dataset"
_PCAP_NAME = "CSIC-2010-HTTP.pcap"
_LABELS_SUBDIR = "GeneratedLabelledFlows"
_LABELS_NAME = "CSIC-2010-HTTP.parquet"
_DST_IP = "10.10.10.10"
_DST_PORT = 80
_START_TS = 1_700_000_000.0
_FLOW_DURATION_US = 100_000
_NORM_ZIP = "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm.csv.zip"
_NORM_TEST_ZIP = (
    "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm_test.csv.zip"
)
_ANOM_ZIP = "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_anom.csv.zip"


CSIC2010_FILES: tuple[DatasetFile, ...] = (
    DatasetFile(
        _NORM_ZIP,
        "zip",
        (f"{_BASE}/{_NORM_ZIP}",),
    ),
    DatasetFile(
        _NORM_TEST_ZIP,
        "zip",
        (f"{_BASE}/{_NORM_TEST_ZIP}",),
    ),
    DatasetFile(
        _ANOM_ZIP,
        "zip",
        (f"{_BASE}/{_ANOM_ZIP}",),
    ),
)


@dataclass(frozen=True)
class _Flow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    timestamp: float
    raw_label: str


@register
class Csic2010:
    name = "csic2010"
    description = "CSIC 2010 HTTP: CSV ZIPs materialized into synthetic HTTP PCAP + labels"

    def download(
        self, target_dir: Path, names: list[str] | None = None
    ) -> list[Path]:
        target_dir.mkdir(parents=True, exist_ok=True)
        requested = _requested_files(names)
        out: list[Path] = []

        for entry in CSIC2010_FILES:
            if entry.name not in requested:
                continue
            dst = target_dir / entry.name
            download_file(entry.urls, dst, entry.kind)
            out.append(dst)

        missing = [
            entry.name for entry in CSIC2010_FILES if not (target_dir / entry.name).exists()
        ]
        if missing:
            raise RuntimeError(
                "CSIC 2010 materialization requires all three CSV ZIP files; missing: "
                + ", ".join(missing)
            )

        pcap_path, labels_path = _materialize(target_dir)
        return [*out, pcap_path, labels_path]

    def label_paths(self, target_dir: Path) -> list[Path]:
        labels_dir = target_dir / _LABELS_SUBDIR
        if not labels_dir.exists():
            return []
        return sorted(labels_dir.rglob("*.parquet")) + sorted(labels_dir.rglob("*.csv"))

    def load_label_index(self, paths: list[Path]) -> FlowLabelIndex:
        return FlowLabelIndex.from_cicids_files(paths)


def _requested_files(names: list[str] | None) -> set[str]:
    available = {entry.name for entry in CSIC2010_FILES}
    if not names:
        return available
    requested = set(names)
    unknown = requested - available
    if unknown:
        raise ValueError(
            f"unknown CSIC 2010 file(s): {sorted(unknown)}; valid files: {sorted(available)}"
        )
    return requested


def _materialize(target_dir: Path) -> tuple[Path, Path]:
    pcap_path = target_dir / _PCAP_NAME
    labels_dir = target_dir / _LABELS_SUBDIR
    labels_path = labels_dir / _LABELS_NAME
    if pcap_path.exists() and labels_path.exists():
        return pcap_path, labels_path

    labels_dir.mkdir(parents=True, exist_ok=True)
    flows: list[_Flow] = []

    from scapy.all import Ether, IP, TCP, Raw, PcapWriter

    writer = PcapWriter(str(pcap_path), linktype=1, sync=True)
    try:
        ordinal = 0
        for entry in CSIC2010_FILES:
            zip_path = target_dir / entry.name
            for row in _iter_zip_rows(zip_path):
                src_ip = _src_ip_for(ordinal)
                src_port = _src_port_for(ordinal)
                timestamp = _START_TS + ordinal * 0.01
                request = _http_request(row)
                packet = (
                    Ether()
                    / IP(src=src_ip, dst=_DST_IP, ttl=64)
                    / TCP(
                        sport=src_port,
                        dport=_DST_PORT,
                        flags="PA",
                        seq=1,
                        ack=1,
                        window=65535,
                    )
                    / Raw(load=request)
                )
                packet.time = timestamp
                writer.write(packet)
                flows.append(
                    _Flow(
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=_DST_IP,
                        dst_port=_DST_PORT,
                        timestamp=timestamp,
                        raw_label=_raw_label(row),
                    )
                )
                ordinal += 1
    finally:
        writer.close()

    _write_labels(labels_path, flows)
    return pcap_path, labels_path


def _iter_zip_rows(zip_path: Path):
    with ZipFile(zip_path) as zf:
        names = [name for name in zf.namelist() if name.lower().endswith(".csv")]
        if not names:
            raise ValueError(f"{zip_path} does not contain a CSV file")
        with zf.open(names[0]) as raw:
            reader = csv.DictReader(TextIOWrapper(raw, encoding="utf-8", newline=""))
            yield from reader


def _http_request(row: dict[str, str]) -> bytes:
    method = _clean(row.get("method")) or "GET"
    url = _clean(row.get("url")) or "/"
    protocol = _clean(row.get("protocol")) or "HTTP/1.1"
    host = _clean(row.get("host")) or _host_from_url(url) or "localhost"
    user_agent = _clean(row.get("userAgent")) or "raptorgate-csic2010"
    cookie = _clean(row.get("cookie"))
    content_type = _clean(row.get("contentType")) or "application/x-www-form-urlencoded"
    body = _clean(row.get("payload")).encode("latin-1", errors="ignore")
    target = _request_target(url)

    headers = [
        f"{method} {target} {protocol}",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Connection: close",
        f"Content-Length: {len(body)}",
    ]
    if cookie:
        headers.append(f"Cookie: {cookie}")
    if body:
        headers.append(f"Content-Type: {content_type}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode("latin-1", errors="ignore") + body


def _request_target(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.scheme:
        return url if url.startswith("/") else f"/{url}"
    path = parsed.path or "/"
    if parsed.query:
        return f"{path}?{parsed.query}"
    return path


def _host_from_url(url: str) -> str | None:
    parsed = urlsplit(url)
    return parsed.netloc or None


def _raw_label(row: dict[str, str]) -> str:
    return "BENIGN" if _clean(row.get("label")).lower() == "norm" else "CSIC_HTTP_ANOMALY"


def _clean(value: str | None) -> str:
    if value is None:
        return ""
    value = value.strip()
    if value.lower() in {"", "null", "none", "nan"}:
        return ""
    return value


def _src_ip_for(ordinal: int) -> str:
    host = ordinal % 254 + 1
    subnet = (ordinal // 254) % 254 + 1
    net = (ordinal // (254 * 254)) % 254 + 1
    return f"10.{net}.{subnet}.{host}"


def _src_port_for(ordinal: int) -> int:
    return 1024 + (ordinal % 60_000)


def _write_labels(path: Path, flows: list[_Flow]) -> None:
    df = pl.DataFrame(
        {
            "Source IP": [flow.src_ip for flow in flows],
            "Destination IP": [flow.dst_ip for flow in flows],
            "Source Port": [flow.src_port for flow in flows],
            "Destination Port": [flow.dst_port for flow in flows],
            "Protocol": [6 for _ in flows],
            "Timestamp": [flow.timestamp for flow in flows],
            "Flow Duration": [_FLOW_DURATION_US for _ in flows],
            "Label": [flow.raw_label for flow in flows],
        }
    )
    df.write_parquet(path)
