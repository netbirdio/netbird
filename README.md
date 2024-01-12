<p align="center">
 <strong>:hatching_chick: New Release! Self-hosting in under 5 min.</strong>
  <a href="https://github.com/netbirdio/netbird#quickstart-with-self-hosted-netbird">
       Learn more
     </a>   
</p>
<br/>
<div align="center">
<p align="center">
  <img width="234" src="docs/media/logo-full.png"/>
</p>
  <p>
     <a href="https://github.com/netbirdio/netbird/blob/main/LICENSE">
       <img src="https://img.shields.io/badge/license-BSD--3-blue" />
     </a> 
   <a href="https://www.codacy.com/gh/netbirdio/netbird/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=netbirdio/netbird&amp;utm_campaign=Badge_Grade"><img src="https://app.codacy.com/project/badge/Grade/e3013d046aec44cdb7462c8673b00976"/></a>
    <br>
    <a href="https://join.slack.com/t/netbirdio/shared_invite/zt-vrahf41g-ik1v7fV8du6t0RwxSrJ96A">
        <img src="https://img.shields.io/badge/slack-@netbird-red.svg?logo=slack"/>
     </a>    
  </p>
</div>


<p align="center">
<strong>
  Start using NetBird at <a href="https://netbird.io/pricing">netbird.io</a>
  <br/>
  See <a href="https://netbird.io/docs/">Documentation</a>
  <br/>
   Join our <a href="https://join.slack.com/t/netbirdio/shared_invite/zt-vrahf41g-ik1v7fV8du6t0RwxSrJ96A">Slack channel</a>
  <br/>
 
</strong>
</p>

<br>

**NetBird combines a configuration-free peer-to-peer private network and a centralized access control system in a single platform, making it easy to create secure private networks for your organization or home.**

**Connect.** NetBird creates a WireGuard-based overlay network that automatically connects your machines over an encrypted tunnel, leaving behind the hassle of opening ports, complex firewall rules, VPN gateways, and so forth.

**Secure.** NetBird enables secure remote access by applying granular access policies, while allowing you to manage them intuitively from a single place. Works universally on any infrastructure.

### Secure peer-to-peer VPN with SSO and MFA in minutes

https://user-images.githubusercontent.com/700848/197345890-2e2cded5-7b7a-436f-a444-94e80dd24f46.mov

### Key features

| Connectivity                             	                                                                                      | Management                                 	                             | Automation                                    	                            | Platforms    	                        |
|---------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|----------------------------------------------------------------------------|---------------------------------------|
| <ul><li> - \[x] Kernel WireGuard </ul></li>                   	                                                                 | <ul><li> - \[x] [Admin Web UI](https://github.com/netbirdio/dashboard) </ul></li>                           	      | <ul><li> - \[x] [Public API](https://docs.netbird.io/api) </ul></li>                                	     | <ul><li> - \[x] Linux </ul></li>    	 |
| <ul><li> - \[x] Peer-to-peer connections </ul></li>             	                                                               | <ul><li> - \[x] Auto peer discovery and configuration </ul></li>  	      | <ul><li> - \[x] [Setup keys for bulk network provisioning](https://docs.netbird.io/how-to/register-machines-using-setup-keys) </ul></li>  	     | <ul><li> - \[x] Mac </ul></li>      	 |
| <ul><li> - \[x] Peer-to-peer encryption </ul></li>              	                                                               | <ul><li> - \[x] [IdP integrations](https://docs.netbird.io/selfhosted/identity-providers) </ul></li>                       	      | <ul><li> - \[x] [Self-hosting quickstart script](https://docs.netbird.io/selfhosted/selfhosted-quickstart) </ul></li>              	 | <ul><li> - \[x] Windows </ul></li>  	 |
| <ul><li> - \[x] Connection relay fallback </ul></li>            	                                                               | <ul><li> - \[x] [SSO & MFA support](https://docs.netbird.io/how-to/installation#running-net-bird-with-sso-login) </ul></li>                      	      | <ul><li> - \[x] IdP groups sync with JWT </ul></li> 	                      | <ul><li> - \[x] Android </ul></li>  	 |
| <ul><li> - \[x] [Routes to external networks](https://docs.netbird.io/how-to/routing-traffic-to-private-networks) </ul></li>  	 | <ul><li> - \[x] [Access control - groups & rules](https://docs.netbird.io/how-to/manage-network-access) </ul></li>      	        | 	                                                                          | <ul><li> - \[x] iOS </ul></li>      	 |
| <ul><li> - \[x] NAT traversal with BPF </ul></li>                                                                               | <ul><li> - \[x] [Private DNS](https://docs.netbird.io/how-to/manage-dns-in-your-network) </ul></li>                            	      | 	                                                                          | <ul><li> - \[x] Docker </ul></li>   	 |
| <ul><li> - \[x] Post-quantum-secure connection through [Rosenpass](https://rosenpass.eu) </ul></li>                             | <ul><li> - \[x] [Multiuser support](https://docs.netbird.io/how-to/add-users-to-your-network) </ul></li>                      	      | 	                                                                          | <ul><li> - \[x] OpenWRT </ul></li>  	 |
| 	                                                                                                                               | <ul><li> - \[x] [Activity logging](https://docs.netbird.io/how-to/monitor-system-and-network-activity) </ul></li>                       	      | 	                                                                          | 	                                     |
| 	                                                                                                                               | <ul><li> - \[x] SSH access management </ul></li>                       	 | 	                                                                          | 	                                     |


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
- The VM should be publicly accessible on TCP ports **80** and **443** and UDP ports: **3478**, **49152-65535**.
- **Public domain** name pointing to the VM.

**Software requirements:**
- Docker installed on the VM with the docker compose plugin ([Docker installation guide](https://docs.docker.com/engine/install/)) or docker with docker-compose in version 2 or higher.
- [jq](https://jqlang.github.io/jq/) installed. In most distributions
  Usually available in the official repositories and can be installed with `sudo apt install jq` or `sudo yum install jq`
- [curl](https://curl.se/) installed.
  Usually available in the official repositories and can be installed with `sudo apt install curl` or `sudo yum install curl`

**Steps**
- Download and run the installation script:
```bash
export NETBIRD_DOMAIN=netbird.example.com; curl -fsSL https://github.com/netbirdio/netbird/releases/latest/download/getting-started-with-zitadel.sh | bash
```
- Once finished, you can manage the resources via `docker-compose`

### A bit on NetBird internals
-  Every machine in the network runs [NetBird Agent (or Client)](client/) that manages WireGuard.
-  Every agent connects to [Management Service](management/) that holds network state, manages peer IPs, and distributes network updates to agents (peers).
-  NetBird agent uses WebRTC ICE implemented in [pion/ice library](https://github.com/pion/ice) to discover connection candidates when establishing a peer-to-peer connection between machines.
-  Connection candidates are discovered with a help of [STUN](https://en.wikipedia.org/wiki/STUN) servers.
-  Agents negotiate a connection through [Signal Service](signal/) passing p2p encrypted messages with candidates.
-  Sometimes the NAT traversal is unsuccessful due to strict NATs (e.g. mobile carrier-grade NAT) and p2p connection isn't possible. When this occurs the system falls back to a relay server called [TURN](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT), and a secure WireGuard tunnel is established via the TURN server. 
 
[Coturn](https://github.com/coturn/coturn) is the one that has been successfully used for STUN and TURN in NetBird setups.

<p float="left" align="middle">
  <img src="https://docs.netbird.io/docs-static/img/architecture/high-level-dia.png" width="700"/>
</p>

See a complete [architecture overview](https://docs.netbird.io/about-netbird/how-netbird-works#architecture) for details.

### Community projects
-  [NetBird on OpenWRT](https://github.com/messense/openwrt-netbird)
-  [NetBird installer script](https://github.com/physk/netbird-installer)

**Note**: The `main` branch may be in an *unstable or even broken state* during development.
For stable versions, see [releases](https://github.com/netbirdio/netbird/releases).

### Support acknowledgement

In November 2022, NetBird joined the [StartUpSecure program](https://www.forschung-it-sicherheit-kommunikationssysteme.de/foerderung/bekanntmachungen/startup-secure) sponsored by The Federal Ministry of Education and Research of The Federal Republic of Germany. Together with [CISPA Helmholtz Center for Information Security](https://cispa.de/en) NetBird brings the security best practices and simplicity to private networking.

![CISPA_Logo_BLACK_EN_RZ_RGB (1)](https://user-images.githubusercontent.com/700848/203091324-c6d311a0-22b5-4b05-a288-91cbc6cdcc46.png)

### Testimonials
We use open-source technologies like [WireGuard®](https://www.wireguard.com/), [Pion ICE (WebRTC)](https://github.com/pion/ice), [Coturn](https://github.com/coturn/coturn), and [Rosenpass](https://rosenpass.eu). We very much appreciate the work these guys are doing and we'd greatly appreciate if you could support them in any way (e.g. giving a star or a contribution).

### Legal
 _WireGuard_ and the _WireGuard_ logo are [registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld.

