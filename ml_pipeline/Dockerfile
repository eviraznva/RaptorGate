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
#     ROCM_VERSION=6.2.0  +  TORCH_ROCM_INDEX=.../whl/rocm6.2
#       - CDNA: gfx900, gfx906, gfx908, gfx90a, gfx942
#       - RDNA 2: gfx1030
#       - RDNA 3: gfx1100, gfx1101 (e.g. 7700 XT, 7800 XT)
#       - RDNA 4: gfx1201 (e.g. 9070 XT, 9070) — needs ROCm 6.2+
#   If a new GPU family lands, bump ROCM_VERSION and TORCH_ROCM_INDEX
#   together and rebuild the image.
#
#   Host contract: only the kernel-mode driver is needed. The host must
#   expose /dev/kfd and /dev/dri (handled by docker-compose.yml). The
#   host does NOT need to install ROCm userland packages; the image is
#   self-contained.

ARG PYTHON_VERSION=3.10
ARG ROCM_VERSION=6.2.0


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

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts /opt/raptorgate-ml/scripts
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

ARG TORCH_ROCM_INDEX=https://download.pytorch.org/whl/rocm6.2
RUN pip install --index-url "${TORCH_ROCM_INDEX}" \
        torch \
 && pip install --upgrade --no-deps pip \
 && apt-get update \
 && apt-get install -y --no-install-recommends patchelf \
 && rm -rf /var/lib/apt/lists/* \
 && find /usr/local/lib/python*/site-packages/torch/lib -maxdepth 1 -type f -name '*.so*' \
        -exec patchelf --clear-execstack {} +

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts /opt/raptorgate-ml/scripts
RUN chmod +x /opt/raptorgate-ml/scripts/*.sh \
 && pip install --no-deps . \
 && pip install .

WORKDIR /data
ENTRYPOINT ["raptorgate-ml"]
CMD ["--help"]
