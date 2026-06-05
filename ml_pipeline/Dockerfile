# syntax=docker/dockerfile:1.7
# Multi-stage Dockerfile for the RaptorGate ML training pipeline.
#
# Build the CUDA variant (NVIDIA GPU):
#   docker build --target raptorgate-ml-cuda -t raptorgate-ml:cuda .
#
# Build the ROCm variant (AMD GPU):
#   docker build --target raptorgate-ml-rocm -t raptorgate-ml:rocm .
#
# Both images expose the `raptorgate-ml` CLI as the entrypoint. Mount your
# data directory at /data (see docker-compose.yml).
#
# Notes on the ROCm variant:
#   The rocm/dev-ubuntu-22.04 base image ships ROCm userland libraries
#   baked into the image filesystem (overlayfs), which avoids the
#   `cannot enable executable stack` failure that happens when the host's
#   libamdhip64.so is bind-mounted from a filesystem that does not grant
#   PROT_EXEC (NTFS, exFAT, etc).
#
#   The torch+rocm wheel bundles its own libamdhip64.so with
#   PT_GNU_STACK PF_X set, which hardened kernels (CachyOS bore, Arch
#   linux-hardened) reject at dlopen time with
#   `cannot enable executable stack as shared object requires`.
#   The patchelf pass below clears that flag from every .so under
#   torch/lib/ so dlopen succeeds.
#
#   GPU support matrix (default ARG values):
#     ROCM_VERSION=6.4.3  +  TORCH_ROCM_INDEX=.../whl/rocm6.4
#       - CDNA: gfx900, gfx906, gfx908, gfx90a, gfx942
#       - RDNA 2: gfx1030
#       - RDNA 3: gfx1100, gfx1101 (e.g. 7700 XT, 7800 XT)
#       - RDNA 4: gfx1200, gfx1201 (e.g. 9060 XT, 9070 XT) — needs ROCm 6.4+
#     gfx1101 is officially supported starting at ROCm 6.4. Older releases
#     (6.2.x, 6.3.x) ship wheels that crash at kernel launch on 7800 XT
#     with "HIP error: invalid device function".
#   If a new GPU family lands, bump ROCM_VERSION and TORCH_ROCM_INDEX
#   together and rebuild the image.
#
#   Host contract: only the kernel-mode driver is needed. The host must
#   expose /dev/kfd and /dev/dri (handled by docker-compose.yml). The
#   host does NOT need to install ROCm userland packages; the image is
#   self-contained.

ARG PYTHON_VERSION=3.10
ARG ROCM_VERSION=6.4.3


# --- Rust builder: tests + builds the raptorgate_pcap maturin wheel.
# Mirrors docker/firewall/dockerfile (same Rust version, same apt deps,
# same two-stage COPY, same nextest gate, same warm-build). The firewall
# pins to bullseye; we use bookworm because Bullseye only ships Python 3.9
# and maturin's abi3-py310 build needs Python 3.10+. The firewall
# installs protoc; raptorgate_pcap's only Rust dep with a proto build is
# ngfw, which uses protoc-bin-vendored — so no system protoc needed, but
# the .proto source files still have to be on disk for ngfw's build.rs
# (it reads ../../proto/* relative to crates/raptorgate/), so we mirror
# the firewall's `COPY proto ./proto` step.
FROM rust:1.93.1-slim-bookworm AS rust-builder

ARG PYTHON_VERSION=3.10
ENV PYTHON_VERSION=${PYTHON_VERSION}
WORKDIR /usr/src/pcap

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
        pkg-config \
        libpcap-dev \
        build-essential \
        ca-certificates \
        curl \
        unzip \
        python3.11 \
        python3.11-dev \
        python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/python3.11 /usr/local/bin/python3 \
 && ln -sf /usr/bin/python3.11 /usr/local/bin/python

# Upgrade pip first; Debian's pip is too old for the `--break-system-packages` flag.
RUN python3 -m pip install --no-cache-dir --break-system-packages --upgrade pip

RUN python3 -m pip install --no-cache-dir --break-system-packages maturin pytest
RUN cargo install --locked cargo-nextest

# Two-stage COPY (firewall pattern): manifest layer is cached across source edits.
COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY ./crates ./crates

# Gate the image build on Rust tests. The firewall uses `-- --skip tls::` to
# dodge a flaky TLS suite; raptorgate_pcap has no such suite.
RUN cargo nextest run -p raptorgate-pcap --no-fail-fast

# Build the wheel into a known path the runtime stages will COPY. Cleanup
# is in the same RUN so /usr/src/pcap/target never lands in a layer — a
# separate RUN would commit the full target/ tree (~5–10 GB) before the
# wheel is copied out.
WORKDIR /usr/src/pcap/crates/raptorgate_pcap
RUN maturin build --release --out /opt/raptorgate-pcap/wheels \
 && rm -rf /usr/src/pcap/target /root/.cargo/registry /root/.cargo/git


# --- CUDA target ------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS raptorgate-ml-cuda

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        libpcap-dev \
        pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/raptorgate-ml

ARG TORCH_CUDA_INDEX=https://download.pytorch.org/whl/cu124
RUN pip install --extra-index-url "${TORCH_CUDA_INDEX}" \
        torch

# raptorgate_pcap Rust extension (built in rust-builder).
COPY --from=rust-builder /opt/raptorgate-pcap/wheels /opt/raptorgate-pcap/wheels
RUN pip install /opt/raptorgate-pcap/wheels/raptorgate_pcap-*.whl

# pytest is needed by entrypoint-pipeline.sh's test gate.
RUN pip install --no-cache-dir pytest

COPY ml_pipeline/pyproject.toml ml_pipeline/README.md ./
COPY ml_pipeline/src ./src
COPY ml_pipeline/tests ./tests
COPY ml_pipeline/scripts /opt/raptorgate-ml/scripts
RUN chmod +x /opt/raptorgate-ml/scripts/*.sh \
 && pip install --no-deps . \
 && pip install .

WORKDIR /data
ENTRYPOINT ["raptorgate-ml"]
CMD ["--help"]


# --- ROCm target ------------------------------------------------------------
FROM rocm/dev-ubuntu-22.04:${ROCM_VERSION} AS raptorgate-ml-rocm

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LD_LIBRARY_PATH=/opt/rocm/lib:/opt/rocm/lib64:${LD_LIBRARY_PATH}

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        libpcap-dev \
        pkg-config \
        python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/python3 /usr/local/bin/python

WORKDIR /opt/raptorgate-ml

ARG TORCH_ROCM_INDEX=https://download.pytorch.org/whl/rocm6.4
RUN pip install --index-url "${TORCH_ROCM_INDEX}" \
        torch \
 && pip install --upgrade --no-deps pip \
 && apt-get update \
 && apt-get install -y --no-install-recommends patchelf \
 && rm -rf /var/lib/apt/lists/* \
 && torch_lib=$(python -c 'import os, torch; print(os.path.join(os.path.dirname(torch.__file__), "lib"))' 2>/dev/null) \
 && if [[ -n "$torch_lib" && -d "$torch_lib" ]]; then \
      find "$torch_lib" -maxdepth 1 -type f -name '*.so*' -not -name '*.hsaco' \
        -exec patchelf --clear-execstack {} +; \
    fi

# raptorgate_pcap Rust extension (built in rust-builder).
COPY --from=rust-builder /opt/raptorgate-pcap/wheels /opt/raptorgate-pcap/wheels
RUN pip install /opt/raptorgate-pcap/wheels/raptorgate_pcap-*.whl

# pytest is needed by entrypoint-pipeline.sh's test gate.
RUN pip install --no-cache-dir pytest

COPY ml_pipeline/pyproject.toml ml_pipeline/README.md ./
COPY ml_pipeline/src ./src
COPY ml_pipeline/tests ./tests
COPY ml_pipeline/scripts /opt/raptorgate-ml/scripts
RUN chmod +x /opt/raptorgate-ml/scripts/*.sh \
 && pip install --no-deps . \
 && pip install .

WORKDIR /data
ENTRYPOINT ["raptorgate-ml"]
CMD ["--help"]
