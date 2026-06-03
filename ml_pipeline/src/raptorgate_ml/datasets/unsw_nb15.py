"""UNSW-NB15 dataset plugin.

UNSW-NB15 was published in 2015 by Nour Moustafa. The original raw PCAPs are
gated behind a data-sharing request, so the only public distributions are
pre-extracted flow CSVs — which the pipeline cannot ingest because the
38-feature vector is derived from PCAP bytes via Scapy + DPI.

This plugin ships the label-side support: if you drop the raw PCAPs into the
download target (obtained via a private mirror or your own capture), the
plugin will find them and the label adapter will build a working
``FlowLabelIndex``. The :meth:`download` method is intentionally a no-op stub
that fails loudly so the gap is obvious.

For a public-PCAP held-out dataset that drops into the same pipeline, see the
``cicids2018`` plugin and use a different day than the one used for training.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

from raptorgate_ml.datasets.registry import register
from raptorgate_ml.labeling import FlowLabelIndex


UNSW_PCAP_FILES: tuple[str, ...] = (
    "UNSW-NB15_1.pcap",
    "UNSW-NB15_2.pcap",
    "UNSW-NB15_3.pcap",
    "UNSW-NB15_4.pcap",
)

UNSW_LABEL_FILES: tuple[str, ...] = (
    "UNSW_NB15_training-set.csv",
    "UNSW_NB15_testing-set.csv",
)


def _load_unsw_labels(csv_path: Path) -> pl.DataFrame:
    df = pl.read_csv(csv_path, ignore_errors=True, infer_schema_length=2000)
    cols = {c.strip().lower(): c for c in df.columns}
    src = {v: k for k, v in cols.items()}

    def pick(*candidates: str) -> str | None:
        for c in candidates:
            key = c.strip().lower()
            if key in cols:
                return cols[key]
        return None

    src_ip = pick("srcip", "src_ip")
    dst_ip = pick("dstip", "dst_ip")
    src_port = pick("sport", "src_port", "source port")
    dst_port = pick("dsport", "dst_port", "destination port")
    proto = pick("proto", "protocol")
    attack = pick("attack_cat", "attack", "label_text")
    binary = pick("label")

    missing = [
        name
        for name, value in (
            ("srcip", src_ip),
            ("dstip", dst_ip),
            ("sport", src_port),
            ("dsport", dst_port),
            ("proto", proto),
            ("label", binary),
        )
        if value is None
    ]
    if missing:
        raise ValueError(
            f"{csv_path} is missing required UNSW-NB15 columns: {', '.join(missing)}"
        )

    out = pl.DataFrame(
        {
            "src_ip": df[src_ip],
            "dst_ip": df[dst_ip],
            "src_port": df[src_port],
            "dst_port": df[dst_port],
            "proto": df[proto],
            "label": df[binary].cast(pl.Int8).map_elements(
                lambda v: "benign" if int(v) == 0 else "malicious",
                return_dtype=pl.Utf8,
            ),
            "attack_label": df[attack] if attack is not None else "malicious",
        }
    )
    return out


@register
class UnswNb15:
    name = "unsw_nb15"
    description = (
        "UNSW-NB15: label-side only; raw PCAPs are gated, drop them into "
        "--target manually (no public PCAP download)"
    )

    def download(
        self, target_dir: Path, names: list[str] | None = None
    ) -> list[Path]:
        raise NotImplementedError(
            "UNSW-NB15 raw PCAPs are not publicly downloadable. "
            "Place UNSW-NB15_{1..4}.pcap and UNSW_NB15_{training,testing}-set.csv "
            f"in {target_dir} manually (private mirror, lab capture, or your own "
            "collection) and re-run the pipeline. For a public-PCAP held-out "
            "dataset, use the `cicids2018` plugin with a different day."
        )

    def label_paths(self, target_dir: Path) -> list[Path]:
        out: list[Path] = []
        for name in UNSW_LABEL_FILES:
            candidate = target_dir / name
            if candidate.exists():
                out.append(candidate)
        return out

    def load_label_index(self, paths: list[Path]) -> FlowLabelIndex:
        idx = FlowLabelIndex()
        for path in paths:
            df = _load_unsw_labels(path)
            normalized = FlowLabelIndex.normalize_dataframe(df)
            idx.absorb(normalized)
        return idx
