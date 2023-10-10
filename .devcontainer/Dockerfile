FROM golang:1.20-bullseye

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends\
        gettext-base \ 
        iptables


WORKDIR /app