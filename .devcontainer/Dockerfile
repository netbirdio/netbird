FROM golang:1.26.10-bookworm

# gopls v0.23.0 is the newest release compatible with Go 1.26
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends\
        gettext-base=0.21-12 \
        iptables=1.8.9-2 \
        libgl1-mesa-dev=22.3.6-1+deb12u2 \
        xorg-dev=1:7.7+23 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && go install -v golang.org/x/tools/gopls@v0.23.0


WORKDIR /app
