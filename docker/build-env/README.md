# Build environments

Dockerfiles that pin the same toolchain CI uses, so a developer can
reproduce a CI build locally without installing platform SDKs on their
workstation. The version pins in each `Dockerfile` must stay in lockstep
with `.github/workflows/`.

## `android/`

Mirrors `.github/workflows/mobile-build-validation.yml` (`android_build`
job). Carries Go 1.25.5, Adopt JDK 11, Android cmdline-tools 8512546,
NDK 23.1.7779620 and gomobile pinned at the CI commit. Use it to
produce `netbird.aar` from `./client/android`:

```bash
docker build -t netbird/build-android docker/build-env/android
docker run --rm -v "$PWD:/src" -w /src netbird/build-android \
    gomobile bind \
    -o netbird.aar \
    -javapkg=io.netbird.gomobile \
    -ldflags="-checklinkname=0 \
              -X golang.zx2c4.com/wireguard/ipc.socketDirectory=/data/data/io.netbird.client/cache/wireguard \
              -X github.com/netbirdio/netbird/version.version=local" \
    ./client/android
```

To build the full Android APK, bind-mount the `android-client` repo as
well and run its own `./gradlew assembleDebug` from inside the
container (the gradle wrapper ships with `android-client`).

## `windows-cross/`

Cross-compiles Windows binaries from Linux using `mingw-w64`. Lets you
verify that `GOOS=windows go build ./...` compiles cleanly without
needing a Windows VM. Cannot run Windows tests — the `golang-test-windows`
CI job executes on a native `windows-latest` runner with wintun.dll
and PsExec, neither of which lives under Linux containers.

```bash
docker build -t netbird/build-windows docker/build-env/windows-cross
docker run --rm -v "$PWD:/src" -w /src netbird/build-windows \
    bash -c 'GOOS=windows GOARCH=amd64 go build ./...'
```

## What is NOT here

- **iOS / macOS**: cannot legally run macOS in Docker (Apple EULA),
  and Xcode is not redistributable. The `ios_build` CI job uses a
  `macos-latest` GitHub runner; locally you need a real Mac.

- **Native Windows tests**: see note above. The Linux+mingw image
  builds, it does not execute Windows-host code paths
  (registry, wintun, services, PsExec workflows).

When CI version pins change, update the corresponding `ARG` lines in
the Dockerfiles and the README's table of versions.
