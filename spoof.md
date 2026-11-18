# NetBird spoofing

This feature changes client-reported system metadata and posture-check results before the client sends them to Management. It also records the real and reported values locally for debugging.

Use only on a controlled test client. The audit files can contain hostnames, paths, process state, network addresses, and hardware identifiers.

## Runtime layout

Set `NB_SPOOF_DIR` to a directory containing `overrides.json`:

```text
/etc/netbird/spoof/
└── overrides.json
```

The client reads `overrides.json` when it gathers system information. It reloads the file after its modification time changes. If `NB_SPOOF_DIR` is set but `overrides.json` does not exist, the client still records real and reported snapshots, but no configured values are overridden.

Runtime output files are written with mode `0600`:

| File | Contents |
| --- | --- |
| `real.json` | System information and posture results before overrides. |
| `reported.json` | System information and posture results after overrides. |
| `posture_checks.json` | Each requested posture path with real and reported results. |
| `posture_checks.log` | Append-only text summary of posture checks. |

Create the directory with restricted permissions:

```bash
sudo install -d -o root -g root -m 0700 /etc/netbird/spoof
sudo chown root:root /etc/netbird/spoof
```

## Configuration

Example `overrides.json`:

```json
{
  "hostname": "reported-host",
  "goOS": "linux",
  "kernel": "reported-kernel",
  "kernelVersion": "6.1.0",
  "platform": "reported-platform",
  "os": "Linux",
  "osVersion": "22.04",
  "netbirdVersion": "0.81.0",
  "uiVersion": "0.81.0",
  "systemSerialNumber": "reported-serial",
  "systemProductName": "reported-product",
  "systemManufacturer": "reported-manufacturer",
  "environment": {
    "cloud": "reported-cloud",
    "platform": "reported-cloud-platform"
  },
  "networkAddresses": [
    {
      "netIP": "10.10.10.10/32",
      "mac": "02:00:00:00:00:10"
    }
  ],
  "flags": {
    "serverSSHAllowed": true,
    "remoteJobsAllowed": true,
    "disableClientRoutes": false,
    "disableServerRoutes": false,
    "disableDNS": false,
    "disableFirewall": false,
    "blockLANAccess": false,
    "blockInbound": false,
    "disableIPv6": false,
    "enableSSHRoot": false,
    "enableSSHSFTP": false,
    "enableSSHLocalPortForwarding": false,
    "enableSSHRemotePortForwarding": false,
    "disableSSHAuth": false,
    "rosenpassEnabled": false,
    "rosenpassPermissive": false
  },
  "postureChecks": {
    "allFiles": false,
    "allProcesses": false,
    "files": {
      "/etc/example/blocked": false,
      "blocked-binary": false
    },
    "processes": {
      "/usr/bin/example-agent": false,
      "unwanted-process": false
    }
  }
}
```

All fields are optional. Omitted system fields and flags retain their real values. Omitted posture-check defaults retain the real result for each path.

### Posture-check settings

Each posture result contains:

- `Exist`, controlled by `files` entries.
- `ProcessIsRunning`, controlled by `processes` entries.

`postureChecks` supports:

| Setting | Effect |
| --- | --- |
| `all` | Set both existence and process results for every requested path. |
| `allFiles` | Set `Exist` for every requested path. |
| `allProcesses` | Set `ProcessIsRunning` for every requested path. |
| `files` | Per-path or per-basename values for `Exist`. |
| `processes` | Per-path or per-basename values for `ProcessIsRunning`. |

A map key can be an exact requested path or its basename. Exact path entries take precedence over basename entries. Unlisted paths keep their real result.

The implementation also accepts these top-level compatibility fields:

```json
{
  "postureCheckAll": false,
  "postureCheckAllFiles": false,
  "postureCheckAllProcesses": false,
  "postureCheckFiles": {
    "/etc/example/blocked": false
  },
  "postureCheckProcesses": {
    "example-agent": false
  }
}
```

Prefer the nested `postureChecks` form for new configurations.

### Flags

The supported flag names are:

```text
rosenpassEnabled
rosenpassPermissive
serverSSHAllowed
remoteJobsAllowed
disableClientRoutes
disableServerRoutes
disableDNS
disableFirewall
blockLANAccess
blockInbound
disableIPv6
enableSSHRoot
enableSSHSFTP
enableSSHLocalPortForwarding
enableSSHRemotePortForwarding
disableSSHAuth
```

Flags can be nested under `flags`, as shown above, or supplied at the top level for compatibility. If both forms define a flag, the top-level value takes precedence.

Validate the JSON before installing it:

```bash
sudo install -o root -g root -m 0600 overrides.json /etc/netbird/spoof/overrides.json
python3 -m json.tool /etc/netbird/spoof/overrides.json >/dev/null
```

## Build the spoof-enabled NetBird binary

Run these commands from the repository root. `client/build.sh` builds the client and verifies that the resulting binary contains the spoofing markers.

```bash
NETBIRD_VERSION=development \
NETBIRD_OUTPUT="$PWD/netbird-spoofed" \
./client/build.sh
```

The output is a normal NetBird client binary with spoofing support. It is not the diagnostic `spoof-test` program.

Build the optional diagnostic program with:

```bash
CGO_ENABLED=0 go build -o spoof-test ./cmd/spoof-test
```

Run it with no arguments to print system information, or pass posture paths to exercise posture overrides:

```bash
NB_SPOOF_DIR=/etc/netbird/spoof ./spoof-test
NB_SPOOF_DIR=/etc/netbird/spoof ./spoof-test /etc/example/blocked /usr/bin/example-agent
```

The diagnostic program writes the same snapshot and posture audit files when `NB_SPOOF_DIR` is set.

## Install for the systemd service

The install helper keeps the spoof-enabled binary in place after package upgrades. It validates the binary markers before replacing the active client.

Create the install helper. It validates the spoofing markers before replacing the package binary:

```bash
sudo tee /usr/local/sbin/netbird-ensure-spoofed >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

SOURCE="${NETBIRD_SPOOF_SOURCE:-/usr/local/libexec/netbird-spoofed}"
TARGET="${NETBIRD_SPOOF_TARGET:-/usr/bin/netbird}"

if [[ "$(id -u)" -ne 0 ]]; then
    printf 'must run as root\n' >&2
    exit 1
fi

if [[ ! -x "$SOURCE" ]]; then
    printf 'spoofing binary is missing: %s\n' "$SOURCE" >&2
    exit 1
fi

markers_file="$(mktemp)"
trap 'rm -f "$markers_file"' EXIT
strings "$SOURCE" >"$markers_file"
for marker in NB_SPOOF_DIR applyPostureCheckOverrides posture_checks.json; do
    if ! grep -F -q "$marker" "$markers_file"; then
        printf 'spoofing binary is missing marker: %s\n' "$marker" >&2
        exit 1
    fi
done

if ! cmp -s "$SOURCE" "$TARGET"; then
    install -o root -g root -m 0755 "$SOURCE" "$TARGET"
fi
EOF
sudo chmod 0755 /usr/local/sbin/netbird-ensure-spoofed
```

Create a systemd drop-in:

```bash
sudo install -d -o root -g root -m 0755 /etc/systemd/system/netbird.service.d
sudo tee /etc/systemd/system/netbird.service.d/spoof.conf >/dev/null <<'EOF'
[Service]
Environment=NB_SPOOF_DIR=/etc/netbird/spoof
ExecStartPre=/usr/local/sbin/netbird-ensure-spoofed
EOF
```

Reload and restart NetBird:

```bash
sudo systemctl daemon-reload
sudo systemctl restart netbird.service
sudo systemctl status netbird.service
```

The helper defaults are:

```text
NETBIRD_SPOOF_SOURCE=/usr/local/libexec/netbird-spoofed
NETBIRD_SPOOF_TARGET=/usr/bin/netbird
```

Override them in the systemd drop-in when the package binary lives elsewhere:

```ini
[Service]
Environment=NB_SPOOF_DIR=/etc/netbird/spoof
Environment=NETBIRD_SPOOF_SOURCE=/usr/local/libexec/netbird-spoofed
Environment=NETBIRD_SPOOF_TARGET=/usr/bin/netbird
ExecStartPre=/usr/local/sbin/netbird-ensure-spoofed
```

Verify that the running binary has spoofing support:

```bash
strings /usr/bin/netbird | grep -E 'NB_SPOOF_DIR|applyPostureCheckOverrides|posture_checks.json'
```

## Foreground or non-systemd use

Set the environment variable for the process that runs NetBird:

```bash
sudo env NB_SPOOF_DIR=/etc/netbird/spoof /usr/local/libexec/netbird-spoofed up
```

For a one-shot diagnostic run, use `spoof-test` as shown above.

## Changing configuration

Edit the file as root, validate it, then trigger another management sync or restart the service:

```bash
sudo editor /etc/netbird/spoof/overrides.json
sudo python3 -m json.tool /etc/netbird/spoof/overrides.json >/dev/null
sudo systemctl restart netbird.service
```

Keep `/etc/netbird/spoof` out of Git. It contains real host observations and reported values.
