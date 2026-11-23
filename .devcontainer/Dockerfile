FROM debian:bookworm

# Features install as root, but the connected user must be non-root so files
# created in the bind-mounted workspace are owned by the matching host user.
RUN groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid vscode --create-home --shell /bin/bash vscode \
    && usermod --append --groups sudo vscode

# Go and its tools are installed by the devcontainer's go feature, which runs
# after this image is built and provides the Go version required by go.mod.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends\
        gettext-base=0.21-12 \
        iptables=1.8.9-2 \
        libgl1-mesa-dev=22.3.6-1+deb12u2 \
        sudo=1.9.13p3-1+deb12u4 \
        xorg-dev=1:7.7+23 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

USER vscode
