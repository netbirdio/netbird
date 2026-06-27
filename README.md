
<div align="center">
  <p align="center">
    <img width="234" src="docs/media/logo-full.png" alt="NetBird logo"/>
  </p>
  <p align="center">
    <a href="https://sonarcloud.io/dashboard?id=netbirdio_netbird">
      <img src="https://sonarcloud.io/api/project_badges/measure?project=netbirdio_netbird&metric=alert_status" alt="SonarCloud alert status"/>
    </a>
    <a href="https://github.com/netbirdio/netbird/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/license-BSD--3-blue" alt="BSD-3 License"/>
    </a>
    <a href="https://docs.netbird.io/slack-url">
      <img src="https://img.shields.io/badge/slack-@netbird-red.svg?logo=slack" alt="NetBird Slack"/>
    </a>
    <a href="https://forum.netbird.io">
      <img src="https://img.shields.io/badge/community%20forum-@netbird-red.svg?logo=discourse" alt="Community forum"/>
    </a>
    <a href="https://gurubase.io/g/netbird">
      <img src="https://img.shields.io/badge/Gurubase-Ask%20NetBird%20Guru-006BFF" alt="Gurubase: Ask NetBird Guru"/>
    </a>
  </p>
</div>

<p align="center">
  <strong>
    Start using NetBird at <a href="https://netbird.io/pricing">netbird.io</a>
    <br/>
    See <a href="https://netbird.io/docs/">Documentation</a>
    <br/>
    Join our <a href="https://docs.netbird.io/slack-url">Slack channel</a> or our <a href="https://forum.netbird.io">Community forum</a>
  </strong>
  <br/>
  <br/>
  <strong>
    🚀 <a href="https://careers.netbird.io">We are hiring! Join us at careers.netbird.io</a>
  </strong>
</p>

**NetBird combines a configuration-free peer-to-peer private network and a centralized access control system in a single platform, making it easy to create secure private networks for your organization or home.**

**Connect.** NetBird creates a WireGuard-based overlay network that automatically connects your machines over an encrypted tunnel, leaving behind the hassle of opening ports, complex firewall rules, VPN gateways, and so forth.

**Secure.** NetBird enables secure remote access by applying granular access policies while allowing you to manage them intuitively from a single place. Works universally on any infrastructure.

> ### 🤖 NetBird Agent Network (Beta)
> Identity-aware access control for AI agents — keyless access to LLM APIs and private
> resources over the encrypted NetBird tunnel. See [`agent-network/`](agent-network/) or
> read the docs at **[docs.netbird.io/agent-network](https://docs.netbird.io/agent-network)**.

https://github.com/user-attachments/assets/10cec749-bb56-4ab3-97af-4e38850108d2

### Self-host NetBird (video)

[![Watch the video](https://img.youtube.com/vi/bZAgpT6nzaQ/0.jpg)](https://youtu.be/bZAgpT6nzaQ)

### Key features

| Connectivity | Management | Security | Automation | Platforms |
|---|---|---|---|---|
| ✓ [Kernel WireGuard](https://docs.netbird.io/about-netbird/why-wireguard-with-netbird) | ✓ [Admin Web UI](https://github.com/netbirdio/dashboard) | ✓ [SSO & MFA support](https://docs.netbird.io/how-to/installation#running-net-bird-with-sso-login) | ✓ [Public API](https://docs.netbird.io/api) | ✓ [Linux](https://docs.netbird.io/get-started/install/linux) |
| ✓ [Peer-to-peer connections](https://docs.netbird.io/about-netbird/how-netbird-works) | ✓ Auto peer discovery and configuration | ✓ [Access control: groups & rules](https://docs.netbird.io/how-to/manage-network-access) | ✓ [Setup keys for bulk provisioning](https://docs.netbird.io/how-to/register-machines-using-setup-keys) | ✓ [macOS](https://docs.netbird.io/get-started/install/macos) |
| ✓ Connection relay fallback | ✓ [IdP integrations](https://docs.netbird.io/selfhosted/identity-providers) | ✓ [Activity logging](https://docs.netbird.io/how-to/audit-events-logging) | ✓ [Self-hosting quickstart script](https://docs.netbird.io/selfhosted/selfhosted-quickstart) | ✓ [Windows](https://docs.netbird.io/get-started/install/windows) |
| ✓ [Routes to external networks](https://docs.netbird.io/how-to/routing-traffic-to-private-networks) | ✓ [Private DNS](https://docs.netbird.io/how-to/manage-dns-in-your-network) | ✓ [Traffic events](https://docs.netbird.io/manage/activity/traffic-events-logging) | ✓ [IdP groups sync with JWT](https://docs.netbird.io/manage/team/idp-sync) | ✓ [Android](https://docs.netbird.io/get-started/install/android) |
| ✓ [Domain-based DNS routes](https://docs.netbird.io/manage/dns/dns-aliases-for-routed-networks) | ✓ [Custom DNS zones](https://docs.netbird.io/manage/dns/custom-zones) | ✓ [Device posture checks](https://docs.netbird.io/how-to/manage-posture-checks) | ✓ [Terraform provider](https://registry.terraform.io/providers/netbirdio/netbird/latest) | ✓ [Android TV](https://docs.netbird.io/get-started/install/android-tv) |
| ✓ [Exit nodes](https://docs.netbird.io/manage/network-routes/use-cases/exit-nodes) | ✓ [Multiuser support](https://docs.netbird.io/how-to/add-users-to-your-network) | ✓ Peer-to-peer encryption | ✓ [Ansible collection](https://github.com/netbirdio/ansible-netbird) | ✓ [iOS](https://docs.netbird.io/get-started/install/ios) |
| ✓ [IPv6 dual-stack overlay](https://docs.netbird.io/manage/settings/ipv6) | ✓ [Multi-account profile switching](https://docs.netbird.io/client/profiles) | ✓ [SSH with central access policies](https://docs.netbird.io/manage/peers/ssh) | | ✓ [Apple TV](https://docs.netbird.io/get-started/install/tvos) |
| ✓ [Browser SSH & RDP](https://docs.netbird.io/manage/peers/browser-client) | | ✓ [Quantum-resistance with Rosenpass](https://netbird.io/knowledge-hub/the-first-quantum-resistant-mesh-vpn) | | ✓ FreeBSD |
| ✓ [Reverse proxy with auto-TLS](https://docs.netbird.io/manage/reverse-proxy) | | ✓ [Periodic re-authentication](https://docs.netbird.io/how-to/enforce-periodic-user-authentication) | | ✓ [pfSense](https://docs.netbird.io/get-started/install/pfsense) |
| | | | | ✓ [OPNsense](https://docs.netbird.io/get-started/install/opnsense) |
| | | | | ✓ [MikroTik RouterOS](https://docs.netbird.io/use-cases/homelab/client-on-mikrotik-router) |
| | | | | ✓ OpenWRT |
| | | | | ✓ [Synology](https://docs.netbird.io/get-started/install/synology) |
| | | | | ✓ [TrueNAS](https://docs.netbird.io/get-started/install/truenas) |
| | | | | ✓ [Proxmox](https://docs.netbird.io/get-started/install/proxmox-ve) |
| | | | | ✓ [Raspberry Pi](https://docs.netbird.io/get-started/install/raspberrypi) |
| | | | | ✓ [Serverless](https://docs.netbird.io/how-to/netbird-on-faas) |
| | | | | ✓ [Container](https://docs.netbird.io/get-started/install/docker) |

### Quickstart with NetBird Cloud

- Download and install NetBird at [https://app.netbird.io/install](https://app.netbird.io/install).
- Follow the steps to sign up with Google, Microsoft, GitHub or your email address.
- Check the NetBird [admin UI](https://app.netbird.io/).

### Quickstart with self-hosted NetBird

This is the quickest way to try self-hosted NetBird. It should take around 5 minutes to get started if you already have a public domain and a VM. Follow the [Advanced guide with a custom identity provider](https://docs.netbird.io/selfhosted/selfhosted-guide#advanced-guide-with-a-custom-identity-provider) for installations with different IdPs.

**Infrastructure requirements:**
- A Linux VM with at least **1 CPU** and **2 GB** of memory.
- The VM should be publicly accessible on TCP ports **80** and **443** and UDP port **3478**.
- A **public domain** name pointing to the VM.

**Software requirements:**
- Docker with the Compose plugin (Compose v2 or higher). See the [Docker installation guide](https://docs.docker.com/engine/install/).

**Steps**
- Download and run the installation script:
```bash
export NETBIRD_DOMAIN=netbird.example.com; curl -fsSL https://github.com/netbirdio/netbird/releases/latest/download/getting-started.sh | bash
```

### A bit on NetBird internals
- Every machine in the network runs the [NetBird agent](client/), which manages WireGuard.
- Every agent connects to the [Management Service](management/), which holds network state, manages peer IPs, and distributes updates to agents.
- Agents use ICE (via [pion/ice](https://github.com/pion/ice)) to discover connection candidates for peer-to-peer connections.
- Candidates are discovered with the help of [STUN](https://en.wikipedia.org/wiki/STUN) servers.
- Agents negotiate a connection through the [Signal Service](signal/), exchanging end-to-end encrypted messages with candidates.
- When NAT traversal fails (e.g. mobile carrier-grade NAT) and a direct p2p connection isn't possible, the system falls back to a [Relay Service](relay/) and a secure WireGuard tunnel is established through it.

<p float="left" align="middle">
  <img src="https://docs.netbird.io/docs-static/img/about-netbird/high-level-dia.png" width="700" alt="NetBird high-level architecture diagram"/>
</p>

See a complete [architecture overview](https://docs.netbird.io/about-netbird/how-netbird-works#architecture) for details.

### Community projects
- [NetBird installer script](https://github.com/physk/netbird-installer)
- [netbird-tui](https://github.com/n0pashkov/netbird-tui) - terminal UI for managing NetBird peers, routes, and settings
- [caddy-netbird](https://github.com/lixmal/caddy-netbird) - Caddy plugin that embeds a NetBird client for proxying HTTP and TCP/UDP traffic through NetBird networks

**Note**: The `main` branch may be in an *unstable or even broken state* during development.
For stable versions, see [releases](https://github.com/netbirdio/netbird/releases).

### Support acknowledgement

In November 2022, NetBird joined the [StartUpSecure program](https://www.forschung-it-sicherheit-kommunikationssysteme.de/foerderung/bekanntmachungen/startup-secure) sponsored by the Federal Ministry of Education and Research of the Federal Republic of Germany. Together with the [CISPA Helmholtz Center for Information Security](https://cispa.de/en), NetBird brings security best practices and simplicity to private networking.

![CISPA_Logo_BLACK_EN_RZ_RGB (1)](https://user-images.githubusercontent.com/700848/203091324-c6d311a0-22b5-4b05-a288-91cbc6cdcc46.png)

### Acknowledgements
We build on open-source technologies like [WireGuard®](https://www.wireguard.com/), [Pion ICE](https://github.com/pion/ice), and [Rosenpass](https://rosenpass.eu). We greatly appreciate the work these projects are doing, and we'd love it if you could support them too (e.g., by starring or contributing).

### Legal
This repository is licensed under the BSD-3-Clause license, which applies to all parts of the repository except for the directories management/, signal/ and relay/.
Those directories are licensed under the GNU Affero General Public License version 3.0 (AGPLv3). See the respective LICENSE files inside each directory.

_WireGuard_ and the _WireGuard_ logo are [registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld.
 

