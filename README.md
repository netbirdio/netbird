
<div align="center">
<br/>
  <br/>
<p align="center">
  <img width="234" src="docs/media/logo-full.png"/>
</p>
  <p>
   <a href="https://img.shields.io/badge/license-BSD--3-blue)">
       <img src="https://sonarcloud.io/api/project_badges/measure?project=netbirdio_netbird&metric=alert_status" />
     </a> 
     <a href="https://github.com/netbirdio/netbird/blob/main/LICENSE">
       <img src="https://img.shields.io/badge/license-BSD--3-blue" />
     </a> 
    <br>
    <a href="https://docs.netbird.io/slack-url">
        <img src="https://img.shields.io/badge/slack-@netbird-red.svg?logo=slack"/>
     </a>
    <a href="https://forum.netbird.io">
        <img src="https://img.shields.io/badge/community forum-@netbird-red.svg?logo=discourse"/>
     </a>  
     <br>
    <a href="https://gurubase.io/g/netbird">
        <img src="https://img.shields.io/badge/Gurubase-Ask%20NetBird%20Guru-006BFF"/>
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
  <br/>
 
</strong>
<br>
<strong>
  🚀 <a href="https://careers.netbird.io">We are hiring! Join us at careers.netbird.io</a>
</strong>
<br>
<br>
<a href="https://registry.terraform.io/providers/netbirdio/netbird/latest">
    New: NetBird terraform provider
  </a> 
</p>

<br>

**NetBird combines a configuration-free peer-to-peer private network and a centralized access control system in a single platform, making it easy to create secure private networks for your organization or home.**

**Connect.** NetBird creates a WireGuard-based overlay network that automatically connects your machines over an encrypted tunnel, leaving behind the hassle of opening ports, complex firewall rules, VPN gateways, and so forth.

**Secure.** NetBird enables secure remote access by applying granular access policies while allowing you to manage them intuitively from a single place. Works universally on any infrastructure.

### Open Source Network Security in a Single Platform

https://github.com/user-attachments/assets/10cec749-bb56-4ab3-97af-4e38850108d2

### Self-Host NetBird (Video)
[![Watch the video](https://img.youtube.com/vi/bZAgpT6nzaQ/0.jpg)](https://youtu.be/bZAgpT6nzaQ)

### Key features

| Connectivity | Management | Security | Automation| Platforms |
|----|----|----|----|----|
| <ul><li>- \[x] Kernel WireGuard</ul></li> | <ul><li>- \[x] [Admin Web UI](https://github.com/netbirdio/dashboard)</ul></li> | <ul><li>- \[x] [SSO & MFA support](https://docs.netbird.io/how-to/installation#running-net-bird-with-sso-login)</ul></li> | <ul><li>- \[x] [Public API](https://docs.netbird.io/api)</ul></li> | <ul><li>- \[x] Linux</ul></li> |
| <ul><li>- \[x] Peer-to-peer connections</ul></li> | <ul><li>- \[x] Auto peer discovery and configuration</ui></li> | <ul><li>- \[x] [Access control - groups & rules](https://docs.netbird.io/how-to/manage-network-access)</ui></li> | <ul><li>- \[x] [Setup keys for bulk network provisioning](https://docs.netbird.io/how-to/register-machines-using-setup-keys)</ui></li> | <ul><li>- \[x] Mac</ui></li> |
| <ul><li>- \[x] Connection relay fallback</ui></li> | <ul><li>- \[x] [IdP integrations](https://docs.netbird.io/selfhosted/identity-providers)</ui></li> | <ul><li>- \[x] [Activity logging](https://docs.netbird.io/how-to/audit-events-logging)</ui></li> | <ul><li>- \[x] [Self-hosting quickstart script](https://docs.netbird.io/selfhosted/selfhosted-quickstart)</ui></li> | <ul><li>- \[x] Windows</ui></li> |
| <ul><li>- \[x] [Routes to external networks](https://docs.netbird.io/how-to/routing-traffic-to-private-networks)</ui></li> | <ul><li>- \[x] [Private DNS](https://docs.netbird.io/how-to/manage-dns-in-your-network)</ui></li> | <ul><li>- \[x] [Device posture checks](https://docs.netbird.io/how-to/manage-posture-checks)</ui></li> | <ul><li>- \[x] IdP groups sync with JWT</ui></li> | <ul><li>- \[x] Android</ui></li> |
| <ul><li>- \[x] NAT traversal with BPF</ui></li> | <ul><li>- \[x] [Multiuser support](https://docs.netbird.io/how-to/add-users-to-your-network)</ui></li> | <ul><li>- \[x] Peer-to-peer encryption</ui></li> || <ul><li>- \[x] iOS</ui></li> |
||| <ul><li>- \[x] [Quantum-resistance with Rosenpass](https://netbird.io/knowledge-hub/the-first-quantum-resistant-mesh-vpn)</ui></li> || <ul><li>- \[x] OpenWRT</ui></li> |
||| <ul><li>- \[x] [Periodic re-authentication](https://docs.netbird.io/how-to/enforce-periodic-user-authentication)</ui></li> || <ul><li>- \[x] [Serverless](https://docs.netbird.io/how-to/netbird-on-faas)</ui></li> |
||||| <ul><li>- \[x] Docker</ui></li> |

### Quickstart with NetBird Cloud

- Download and install NetBird at [https://app.netbird.io/install](https://app.netbird.io/install)
- Follow the steps to sign-up with Google, Microsoft, GitHub or your email address.
- Check NetBird [admin UI](https://app.netbird.io/).
- Add more machines.

### Quickstart with self-hosted NetBird

> This is the quickest way to try self-hosted NetBird. It should take around 5 minutes to get started if you already have a public domain and a VM.
Follow the [Advanced guide with a custom identity provider](https://docs.netbird.io/selfhosted/selfhosted-guide#advanced-guide-with-a-custom-identity-provider) for installations with different IDPs.

**Infrastructure requirements:**
- A Linux VM with at least **1CPU** and **2GB** of memory.
- The VM should be publicly accessible on TCP ports **80** and **443** and UDP port: **3478**.
- **Public domain** name pointing to the VM.

**Software requirements:**
- Docker installed on the VM with the docker-compose plugin ([Docker installation guide](https://docs.docker.com/engine/install/)) or docker with docker-compose in version 2 or higher.
- [jq](https://jqlang.github.io/jq/) installed. In most distributions
  Usually available in the official repositories and can be installed with `sudo apt install jq` or `sudo yum install jq`
- [curl](https://curl.se/) installed.
  Usually available in the official repositories and can be installed with `sudo apt install curl` or `sudo yum install curl`

**Steps**
- Download and run the installation script:
```bash
export NETBIRD_DOMAIN=netbird.example.com; curl -fsSL https://github.com/netbirdio/netbird/releases/latest/download/getting-started.sh | bash
```
- Once finished, you can manage the resources via `docker-compose`

### A bit on NetBird internals
-  Every machine in the network runs [NetBird Agent (or Client)](client/) that manages WireGuard.
-  Every agent connects to [Management Service](management/) that holds network state, manages peer IPs, and distributes network updates to agents (peers).
-  NetBird agent uses WebRTC ICE implemented in [pion/ice library](https://github.com/pion/ice) to discover connection candidates when establishing a peer-to-peer connection between machines.
-  Connection candidates are discovered with the help of [STUN](https://en.wikipedia.org/wiki/STUN) servers.
-  Agents negotiate a connection through [Signal Service](signal/) passing p2p encrypted messages with candidates.
-  Sometimes the NAT traversal is unsuccessful due to strict NATs (e.g. mobile carrier-grade NAT) and a p2p connection isn't possible. When this occurs the system falls back to a relay server called [TURN](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT), and a secure WireGuard tunnel is established via the TURN server. 
 
[Coturn](https://github.com/coturn/coturn) is the one that has been successfully used for STUN and TURN in NetBird setups.

<p float="left" align="middle">
  <img src="https://docs.netbird.io/docs-static/img/about-netbird/high-level-dia.png" width="700"/>
</p>

See a complete [architecture overview](https://docs.netbird.io/about-netbird/how-netbird-works#architecture) for details.

### Community projects
-  [NetBird installer script](https://github.com/physk/netbird-installer)
-  [NetBird ansible collection by Dominion Solutions](https://galaxy.ansible.com/ui/repo/published/dominion_solutions/netbird/)

**Note**: The `main` branch may be in an *unstable or even broken state* during development.
For stable versions, see [releases](https://github.com/netbirdio/netbird/releases).

### Support acknowledgement

In November 2022, NetBird joined the [StartUpSecure program](https://www.forschung-it-sicherheit-kommunikationssysteme.de/foerderung/bekanntmachungen/startup-secure) sponsored by The Federal Ministry of Education and Research of The Federal Republic of Germany. Together with [CISPA Helmholtz Center for Information Security](https://cispa.de/en) NetBird brings the security best practices and simplicity to private networking.

![CISPA_Logo_BLACK_EN_RZ_RGB (1)](https://user-images.githubusercontent.com/700848/203091324-c6d311a0-22b5-4b05-a288-91cbc6cdcc46.png)

### Testimonials
We use open-source technologies like [WireGuard®](https://www.wireguard.com/), [Pion ICE (WebRTC)](https://github.com/pion/ice), [Coturn](https://github.com/coturn/coturn), and [Rosenpass](https://rosenpass.eu). We very much appreciate the work these guys are doing and we'd greatly appreciate if you could support them in any way (e.g., by giving a star or a contribution).

### Legal
This repository is licensed under BSD-3-Clause license that applies to all parts of the repository except for the directories management/, signal/ and relay/.
Those directories are licensed under the GNU Affero General Public License version 3.0 (AGPLv3). See the respective LICENSE files inside each directory.

_WireGuard_ and the _WireGuard_ logo are [registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld.
 

