FROM gcr.io/distroless/base:debug
ENV WT_LOG_FILE=console
SHELL ["/busybox/sh","-c"]
RUN sed -i -E 's/(^root:.+)\/sbin\/nologin/\1\/busybox\/sh/g' /etc/passwd
ENTRYPOINT [ "/go/bin/netbird","up"]
COPY netbird /go/bin/netbird