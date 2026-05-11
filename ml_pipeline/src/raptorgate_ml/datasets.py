import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import polars as pl
import requests
from tqdm import tqdm

_MAX_RETRIES_PER_URL = 10
_BACKOFF_CAP_SECS = 60.0
_CHUNK_SIZE = 1 << 20
_REQUEST_TIMEOUT = 60
_TRANSIENT_EXCEPTIONS = (
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
)

DownloadKind = Literal["pcap", "zip", "parquet"]


@dataclass(frozen=True)
class DatasetFile:
    name: str
    kind: DownloadKind
    urls: tuple[str, ...]


OFFICIAL_BASES: tuple[str, ...] = (
    "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset",
    "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017",
    "https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset",
    "https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017",
)

HF_PCAP_BASE = "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap"
HF_TRAFFIC_LABELS_BASE = (
    "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/traffic_labels"
)

HF_TRAFFIC_LABEL_FILES: tuple[str, ...] = (
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet",
    "Monday-WorkingHours.pcap_ISCX.csv.parquet",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet",
    "Tuesday-WorkingHours.pcap_ISCX.csv.parquet",
    "Wednesday-workingHours.pcap_ISCX.csv.parquet",
)

PCAP_MAGIC_HEADERS: tuple[bytes, ...] = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)
ZIP_MAGIC_HEADERS: tuple[bytes, ...] = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
)
PARQUET_MAGIC = b"PAR1"


def _pcap_urls(*remote_names: str) -> tuple[str, ...]:
    urls: list[str] = []
    for remote_name in remote_names:
        urls.append(f"{HF_PCAP_BASE}/{remote_name}?download=true")
        urls.extend(f"{base}/PCAPs/{remote_name}" for base in OFFICIAL_BASES)
    return tuple(dict.fromkeys(urls))


def _zip_urls(*remote_names: str) -> tuple[str, ...]:
    urls: list[str] = []
    for remote_name in remote_names:
        urls.extend(f"{base}/{remote_name}" for base in OFFICIAL_BASES)
        urls.extend(f"{base}/CSVs/{remote_name}" for base in OFFICIAL_BASES)
    return tuple(dict.fromkeys(urls))


CICIDS2017_FILES: tuple[DatasetFile, ...] = (
    DatasetFile("Monday-WorkingHours.pcap", "pcap", _pcap_urls("Monday-WorkingHours.pcap")),
    DatasetFile("Tuesday-WorkingHours.pcap", "pcap", _pcap_urls("Tuesday-WorkingHours.pcap")),
    DatasetFile(
        "Wednesday-WorkingHours.pcap",
        "pcap",
        _pcap_urls("Wednesday-WorkingHours.pcap", "Wednesday-workingHours.pcap"),
    ),
    DatasetFile("Thursday-WorkingHours.pcap", "pcap", _pcap_urls("Thursday-WorkingHours.pcap")),
    DatasetFile("Friday-WorkingHours.pcap", "pcap", _pcap_urls("Friday-WorkingHours.pcap")),
    DatasetFile("GeneratedLabelledFlows.zip", "zip", _zip_urls("GeneratedLabelledFlows.zip")),
)


def _looks_like_html(prefix: bytes) -> bool:
    head = prefix.lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def _matches_magic(prefix: bytes, kind: DownloadKind) -> bool:
    if kind == "pcap":
        return any(prefix.startswith(magic) for magic in PCAP_MAGIC_HEADERS)
    if kind == "zip":
        return any(prefix.startswith(magic) for magic in ZIP_MAGIC_HEADERS)
    return prefix.startswith(PARQUET_MAGIC)


def _read_prefix(path: Path, size: int = 64) -> bytes:
    if not path.exists() or path.stat().st_size == 0:
        return b""
    with open(path, "rb") as f:
        return f.read(size)


def _is_valid_file(path: Path, kind: DownloadKind) -> bool:
    prefix = _read_prefix(path)
    return bool(prefix) and not _looks_like_html(prefix) and _matches_magic(prefix, kind)


def _resumable_size(tmp: Path, kind: DownloadKind) -> int:
    if not tmp.exists() or tmp.stat().st_size == 0:
        return 0
    if not _is_valid_file(tmp, kind):
        tmp.unlink()
        return 0
    return tmp.stat().st_size


def _stream_append(
    resp: requests.Response,
    tmp: Path,
    kind: DownloadKind,
    existing: int,
    total: int | None,
    desc: str,
) -> None:
    mode = "ab" if existing > 0 else "wb"
    validated = existing > 0
    with open(tmp, mode) as f, tqdm(
        initial=existing,
        total=total,
        unit="B",
        unit_scale=True,
        desc=desc,
    ) as bar:
        for chunk in resp.iter_content(chunk_size=_CHUNK_SIZE):
            if not chunk:
                continue
            if not validated:
                if _looks_like_html(chunk):
                    raise ValueError("server returned HTML instead of dataset bytes")
                if not _matches_magic(chunk, kind):
                    raise ValueError(f"unexpected file signature for {kind}")
                validated = True
            f.write(chunk)
            bar.update(len(chunk))


def _download_url_with_resume(url: str, tmp: Path, kind: DownloadKind, desc: str) -> None:
    for attempt in range(_MAX_RETRIES_PER_URL):
        existing = _resumable_size(tmp, kind)
        headers = {"User-Agent": "raptorgate-ml/0.1"}
        if existing > 0:
            headers["Range"] = f"bytes={existing}-"
        try:
            with requests.get(
                url,
                stream=True,
                timeout=_REQUEST_TIMEOUT,
                headers=headers,
            ) as resp:
                ctype = resp.headers.get("content-type", "").lower()
                if "text/html" in ctype or "application/xhtml+xml" in ctype:
                    raise ValueError(
                        f"unexpected content type {ctype or '<missing>'}"
                    )
                if resp.status_code == 416:
                    if _is_valid_file(tmp, kind):
                        return
                    raise ValueError(
                        "range not satisfiable; delete .part file and retry"
                    )
                if existing > 0 and resp.status_code == 200:
                    tmp.unlink()
                    existing = 0
                resp.raise_for_status()
                remaining = int(resp.headers.get("content-length", 0))
                total = existing + remaining if remaining else None
                _stream_append(resp, tmp, kind, existing, total, desc)
            return
        except _TRANSIENT_EXCEPTIONS:
            if attempt + 1 >= _MAX_RETRIES_PER_URL:
                raise
            time.sleep(min(2**attempt, _BACKOFF_CAP_SECS))


def download_file(urls: tuple[str, ...], target: Path, kind: DownloadKind) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if _is_valid_file(target, kind):
        return

    tmp = target.with_suffix(target.suffix + ".part")
    errors: list[str] = []

    for url in urls:
        try:
            _download_url_with_resume(url, tmp, kind, target.name)
            if not _is_valid_file(tmp, kind):
                raise ValueError("downloaded file failed signature validation")
            tmp.replace(target)
            return
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    raise RuntimeError(
        f"failed to download {target.name}; tried {len(urls)} sources:\n"
        + "\n".join(errors)
    )


def _download_generated_labelled_flows(target_dir: Path) -> Path:
    zip_target = target_dir / "GeneratedLabelledFlows.zip"
    try:
        download_file(_zip_urls("GeneratedLabelledFlows.zip"), zip_target, "zip")
        return zip_target
    except RuntimeError:
        parquet_dir = target_dir / "GeneratedLabelledFlows"
        parquet_dir.mkdir(parents=True, exist_ok=True)
        for name in HF_TRAFFIC_LABEL_FILES:
            download_file(
                (f"{HF_TRAFFIC_LABELS_BASE}/{name}?download=true",),
                parquet_dir / name,
                "parquet",
            )
        return parquet_dir


def download_cicids2017(target_dir: Path, names: list[str] | None = None) -> list[Path]:
    out: list[Path] = []
    for df in CICIDS2017_FILES:
        if names and df.name not in names:
            continue
        if df.name == "GeneratedLabelledFlows.zip":
            out.append(_download_generated_labelled_flows(target_dir))
            continue
        dst = target_dir / df.name
        download_file(df.urls, dst, df.kind)
        out.append(dst)
    return out


def load_cicids_labels(csv_path: Path) -> pl.DataFrame:
    if csv_path.suffix.lower() == ".parquet":
        df = pl.read_parquet(csv_path)
    else:
        df = pl.read_csv(csv_path, ignore_errors=True, infer_schema_length=2000)
    cols = {c.strip(): c for c in df.columns}
    renames: dict[str, str] = {}
    for src, dst in (
        ("Source IP", "src_ip"),
        ("Destination IP", "dst_ip"),
        ("Source Port", "src_port"),
        ("Destination Port", "dst_port"),
        ("Protocol", "proto"),
        ("Timestamp", "timestamp"),
        ("Flow Duration", "flow_duration_us"),
        ("Label", "label"),
    ):
        if src in cols:
            renames[cols[src]] = dst
    df = df.rename(renames)
    keep = [
        c
        for c in (
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "proto",
            "timestamp",
            "flow_duration_us",
            "label",
        )
        if c in df.columns
    ]
    return df.select(keep)
