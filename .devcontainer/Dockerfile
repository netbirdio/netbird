FROM golang:1.20-bullseye

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends\
        gettext-base=0.21-4 \ 
        iptables=1.8.7-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app
