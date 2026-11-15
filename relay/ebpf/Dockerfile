FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    gcc \
    make \
    libbpf-dev \
    linux-headers-generic \
    pkg-config \
    git \
    ca-certificates \
    curl \
    wget \
    tar \
    libbpf-dev \
    libc6-dev-i386-amd64-cross

RUN wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    rm go1.23.0.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /src

ENTRYPOINT ["/bin/bash"]

