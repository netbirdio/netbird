#!/usr/bin/env bash

cat >&2 <<'EOF'
ERROR: This legacy installation script has been retired and no longer runs.

Dex support is not deprecated. For new deployments, use getting-started.sh:

https://docs.netbird.io/selfhosted/selfhosted-quickstart

The current installer includes NetBird's embedded Dex-based identity provider.
Local users and external identity providers can be managed through the
NetBird Dashboard:

https://docs.netbird.io/selfhosted/identity-providers/local

This compatibility notice will be removed in NetBird v0.80.
EOF

exit 1
