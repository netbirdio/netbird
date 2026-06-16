# Android build environment.
#
# Mirrors the toolchain pinned by .github/workflows/mobile-build-validation.yml
# so a `gomobile bind` against ./client/android in this image produces the
# same netbird.aar that CI builds.
#
# Tooling versions (must stay in sync with the CI workflow):
#   - Ubuntu 22.04 (matches the ubuntu-latest GitHub runner)
#   - Go 1.25.5 (matches go.mod)
#   - Adopt JDK 11 (matches actions/setup-java@v3 java-version: 11, distribution: adopt)
#   - Android SDK cmdline-tools 8512546
#   - Android NDK 23.1.7779620
#   - gomobile commit v0.0.0-20251113184115-a159579294ab
#
# Usage (from the netbird repo root):
#
#   docker build -t netbird/build-android docker/build-env/android
#
#   # bind the netbird checkout in and run the same gomobile command CI runs
#   docker run --rm -v "$PWD:/src" -w /src netbird/build-android \
#       gomobile bind \
#       -o netbird.aar \
#       -javapkg=io.netbird.gomobile \
#       -ldflags="-checklinkname=0 \
#                 -X golang.zx2c4.com/wireguard/ipc.socketDirectory=/data/data/io.netbird.client/cache/wireguard \
#                 -X github.com/netbirdio/netbird/version.version=local" \
#       ./client/android
#
# To build the full APK, mount the android-client repo too and run
# `./gradlew assembleDebug` from /android-client (this image carries
# gradle's prerequisites JDK + Android SDK but not the gradle wrapper —
# that ships with android-client).

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# Versions — bump in lockstep with .github/workflows/mobile-build-validation.yml.
ARG GO_VERSION=1.25.5
ARG ANDROID_CMDLINE_TOOLS_VERSION=8512546
ARG ANDROID_NDK_VERSION=23.1.7779620
ARG GOMOBILE_VERSION=v0.0.0-20251113184115-a159579294ab

ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_NDK_HOME=${ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION}
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV GOPATH=/go
ENV GOTOOLCHAIN=local
ENV CGO_ENABLED=0
ENV PATH=${GOPATH}/bin:/usr/local/go/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${JAVA_HOME}/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        unzip \
        git \
        openjdk-11-jdk-headless \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Go (matches go.mod). actions/setup-go fetches the same tarball.
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        | tar -C /usr/local -xz \
    && go version

# Install Android SDK command-line tools, accept licenses, install NDK.
RUN mkdir -p "${ANDROID_HOME}/cmdline-tools" \
    && curl -fsSL -o /tmp/cmdline.zip \
        "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_VERSION}_latest.zip" \
    && unzip -q /tmp/cmdline.zip -d "${ANDROID_HOME}/cmdline-tools" \
    && mv "${ANDROID_HOME}/cmdline-tools/cmdline-tools" "${ANDROID_HOME}/cmdline-tools/latest" \
    && rm /tmp/cmdline.zip \
    && yes | sdkmanager --licenses > /dev/null \
    && sdkmanager --install "ndk;${ANDROID_NDK_VERSION}" "platform-tools" > /dev/null

# Install gomobile at the same commit CI pins. Don't run `gomobile init` here:
# `init` resolves the NDK at runtime, do it on the first bind in the mounted
# workspace so the cache lands on the host volume.
RUN GOBIN=/usr/local/bin go install "golang.org/x/mobile/cmd/gomobile@${GOMOBILE_VERSION}" \
    && gomobile version

WORKDIR /src

# Default entrypoint is a plain shell so the image is composable: callers pass
# the full gomobile / gradle command they want to run.
CMD ["/bin/bash"]
