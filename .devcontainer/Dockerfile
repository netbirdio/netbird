FROM golang:1.25-bookworm

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        gettext-base \
        iptables \
        libgl1-mesa-dev \
        xorg-dev \
        libayatana-appindicator3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && go install -v golang.org/x/tools/gopls@latest


WORKDIR /app
