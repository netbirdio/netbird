FROM golang:1.25-bookworm

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends\
        gettext-base=0.21-12 \
        iptables=1.8.9-2 \
        libgl1-mesa-dev=22.3.6-1+deb12u1 \
        xorg-dev=1:7.7+23 \
        libayatana-appindicator3-dev=0.5.92-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && go install -v golang.org/x/tools/gopls@latest


WORKDIR /app
