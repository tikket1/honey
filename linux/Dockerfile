# The honey Linux side: a toolchain + runtime image for building the C loader
# and running honey's emitted BPF bytecode against a real kernel.
#
# We don't ship our own kernel — we borrow the one Docker Desktop already
# runs (6.12 linuxkit, with BPF + BTF). This image only carries userspace:
# a C compiler, libbpf, and bpftool.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        gcc \
        make \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        iputils-ping \
        iproute2 \
        systemtap-sdt-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
