<div align="center">

<p align="center">
  <img width="250" src="docs/media/logo-full.png"/>
</p>

  <p>
     <a href="https://github.com/wiretrustee/wiretrustee/blob/main/LICENSE">
       <img src="https://img.shields.io/badge/license-BSD--3-blue" />
     </a> 
     <a href="https://hub.docker.com/r/wiretrustee/wiretrustee/tags">
        <img src="https://img.shields.io/docker/pulls/wiretrustee/wiretrustee" />
     </a>  
    <img src="https://badgen.net/badge/Open%20Source%3F/Yes%21/blue?icon=github" />
    <br>
    <a href="https://www.codacy.com/gh/wiretrustee/wiretrustee/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=wiretrustee/wiretrustee&amp;utm_campaign=Badge_Grade"><img src="https://app.codacy.com/project/badge/Grade/d366de2c9d8b4cf982da27f8f5831809"/></a>
     <a href="https://goreportcard.com/report/wiretrustee/wiretrustee">
        <img src="https://goreportcard.com/badge/github.com/wiretrustee/wiretrustee?style=flat-square" />
     </a>
    <br>
    <a href="https://join.slack.com/t/wiretrustee/shared_invite/zt-vrahf41g-ik1v7fV8du6t0RwxSrJ96A">
        <img src="https://img.shields.io/badge/slack-@wiretrustee-red.svg?logo=slack"/>
     </a>    
  </p>
</div>


<p align="center">
<strong>
  Start using Wiretrustee at <a href="https://app.wiretrustee.com/">app.wiretrustee.com</a>
  <br/>
  See <a href="https://docs.wiretrustee.com">Documentation</a>
  <br/>
   Join our <a href="https://join.slack.com/t/wiretrustee/shared_invite/zt-vrahf41g-ik1v7fV8du6t0RwxSrJ96A">Slack channel</a>
  <br/>
 
</strong>
</p>

<br>

**Wiretrustee is an open-source VPN platform built on top of WireGuard® making it easy to create secure private networks for your organization or home.**

It requires zero configuration effort leaving behind the hassle of opening ports, complex firewall rules, VPN gateways, and so forth.

**Wiretrustee automates Wireguard-based networks, offering a management layer with:**
* Centralized Peer IP management with a UI dashboard.
* Encrypted peer-to-peer connections without a centralized VPN gateway.
* Automatic Peer discovery and configuration.
* UDP hole punching to establish peer-to-peer connections behind NAT, firewall, and without a public static IP.
* Connection relay fallback in case a peer-to-peer connection is not possible.
* Multitenancy (coming soon).
* Client application SSO with MFA (coming soon).
* Access Controls (coming soon).
* Activity Monitoring (coming soon).
* Private DNS (coming soon)

### Secure peer-to-peer VPN in minutes
<p float="left" align="middle">
  <img src="docs/media/peerA.gif" width="400"/> 
  <img src="docs/media/peerB.gif" width="400"/>
</p>

**Note**: The `main` branch may be in an *unstable or even broken state* during development. For stable versions, see [releases](https://github.com/wiretrustee/wiretrustee/releases).

Hosted version: 
[https://app.wiretrustee.com/](https://app.wiretrustee.com/peers). 

[UI Dashboard Repo](https://github.com/wiretrustee/wiretrustee-dashboard)


### A bit on Wiretrustee internals
* Wiretrustee features a Management Service that offers peer IP management and network updates distribution (e.g. when a new peer joins the network).
* Wiretrustee uses WebRTC ICE implemented in [pion/ice library](https://github.com/pion/ice) to discover connection candidates when establishing a peer-to-peer connection between devices.
* Peers negotiate connection through [Signal Service](signal/).
* Signal Service uses public Wireguard keys to route messages between peers.
  Contents of the messages sent between peers through the signaling server are encrypted with Wireguard keys, making it impossible to inspect them.
* Occasionally, the NAT traversal is unsuccessful due to strict NATs (e.g. mobile carrier-grade NAT). When this occurs the system falls back to the relay server (TURN), and a secure Wireguard tunnel is established via the TURN server. [Coturn](https://github.com/coturn/coturn) is the one that has been successfully used for STUN and TURN in Wiretrustee setups.

<p float="left" align="middle">
  <img src="https://docs.wiretrustee.com/img/architecture/high-level-dia.png" width="700"/>
</p>


### Product Roadmap
- [Public Roadmap](https://github.com/wiretrustee/wiretrustee/projects/2)
- [Public Roadmap Progress Tracking](https://github.com/wiretrustee/wiretrustee/projects/1)

### Client Installation
#### Linux

**APT/Debian**
1. Add the repository:
    ```shell
    sudo apt-get update
    sudo apt-get install ca-certificates curl gnupg -y
    curl -L https://pkgs.wiretrustee.com/debian/public.key | sudo apt-key add -
    echo 'deb https://pkgs.wiretrustee.com/debian stable main' | sudo tee /etc/apt/sources.list.d/wiretrustee.list
    ```
2. Install the package
    ```shell
    sudo apt-get update
    sudo apt-get install wiretrustee
    ```
**RPM/Red hat**
1. Add the repository:
    ```shell
    cat <<EOF | sudo tee /etc/yum.repos.d/wiretrustee.repo
    [Wiretrustee]
    name=Wiretrustee
    baseurl=https://pkgs.wiretrustee.com/yum/
    enabled=1
    gpgcheck=0
    gpgkey=https://pkgs.wiretrustee.com/yum/repodata/repomd.xml.key
    repo_gpgcheck=1
    EOF
    ```
2. Install the package
    ```shell
    sudo yum install wiretrustee
    ```
#### MACOS
**Brew install**
1. Download and install Brew at https://brew.sh/
2. Install the client
  ```shell
  brew install wiretrustee/client/wiretrustee
  ```
**Installation from binary** 
1. Checkout Wiretrustee [releases](https://github.com/wiretrustee/wiretrustee/releases/latest)
2. Download the latest release (**Switch VERSION to the latest**):
  ```shell
  curl -o ./wiretrustee_<VERSION>_darwin_amd64.tar.gz https://github.com/wiretrustee/wiretrustee/releases/download/v<VERSION>/wiretrustee_<VERSION>_darwin_amd64.tar.gz
  ```
3. Decompress
  ```shell
  tar xcf ./wiretrustee_<VERSION>_darwin_amd64.tar.gz
  sudo mv wiretrusee /usr/bin/wiretrustee
  chmod +x /usr/bin/wiretrustee
  ```
After that you may need to add /usr/bin in your PATH environment variable:
  ````shell
  export PATH=$PATH:/usr/bin
  ````
4. Install and run the service
```shell
  sudo wiretrustee service install
  sudo wiretrustee service start    
```

#### Windows
1. Checkout Wiretrustee [releases](https://github.com/wiretrustee/wiretrustee/releases/latest)
2. Download the latest Windows release installer ```wiretrustee_installer_<VERSION>_windows_amd64.exe``` (**Switch VERSION to the latest**):
3. Proceed with installation steps
4. This will install the client in the C:\\Program Files\\Wiretrustee and add the client service
5. After installing, you can follow the [Client Configuration](#Client-Configuration) steps.
> To uninstall the client and service, you can use Add/Remove programs

### Client Configuration
1. Login to the Management Service. You need to have a `setup key` in hand (see ).

For **Unix** systems:
  ```shell
  sudo wiretrustee up --setup-key <SETUP KEY>
  ```
For  **Windows** systems, start powershell as administrator and:
  ```shell
  wiretrustee up --setup-key <SETUP KEY>
   ```
For **Docker**, you can run with the following command:
```shell
docker run --network host --privileged --rm -d -e WT_SETUP_KEY=<SETUP KEY> -v wiretrustee-client:/etc/wiretrustee wiretrustee/wiretrustee:<TAG>
```
> TAG > 0.3.0 version

Alternatively, if you are hosting your own Management Service provide `--management-url` property pointing to your Management Service:
  ```shell
  sudo wiretrustee up --setup-key <SETUP KEY> --management-url https://localhost:33073
  ```

> You could also omit the `--setup-key` property. In this case, the tool will prompt for the key.


2. Check your IP:
  For **MACOS** you will just start the service:
  ````shell
  sudo ipconfig getifaddr utun100
  ````   
For **Linux** systems:
  ```shell
  ip addr show wt0
  ```
For **Windows** systems:
  ```shell
  netsh interface ip show config name="wt0"
  ```

3. Repeat on other machines.  

### Troubleshooting

1.  If you have specified a wrong `--management-url` (e.g., just by mistake when self-hosting)
    to override it you can do the following:

    ```shell
    sudo wiretrustee down
    sudo wiretrustee up --management-url https://<CORRECT HOST:PORT>/
    ```

2.  If you are using self-hosted version and haven't specified `--management-url`, the client app will use the default URL
    which is ```https://api.wiretrustee.com:33073```.
    
    To override it see solution #1 above.

### Running Dashboard, Management, Signal and Coturn
See [Self-Hosting Guide](https://docs.wiretrustee.com/getting-started/self-hosting)


### Legal
 [WireGuard](https://wireguard.com/) is a registered trademark of Jason A. Donenfeld.

