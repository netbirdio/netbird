#!/usr/bin/env bash

cat >&2 <<'EOF'
ERROR: This legacy installation script has been retired and no longer runs.

For new deployments, use getting-started.sh:

https://docs.netbird.io/selfhosted/selfhosted-quickstart

The current installer includes NetBird's embedded Dex-based identity provider.
Zitadel can be added as an external identity provider directly through the
NetBird Dashboard:

https://docs.netbird.io/selfhosted/identity-providers/zitadel

Standalone Zitadel and other custom identity-provider deployments remain
supported through the advanced guide:

https://docs.netbird.io/selfhosted/selfhosted-guide

EOF

exit 1
