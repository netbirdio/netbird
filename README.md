# Wiretrustee

#### See [Documentation](docs/README.md) for more information about Wiretrustee.

A WireGuard®-based mesh network that connects your devices into a single private network.

**Note**: The `main` branch may be in an *unstable or even broken state* during development. For stable versions, see [releases](https://github.com/wiretrustee/wiretrustee/releases).

Hosted demo version: 
[https://app.wiretrustee.com/](https://app.wiretrustee.com/peers). 

The number of peers is limited to 15.

Please don't use the hosted demonstration version for production purposes. We appreciate your usage of the demonstration version and will love to hear your feedback, please reach out via Issue or [Slack](https://wiretrustee.slack.com/).

[UI Dashboard Repo](https://github.com/wiretrustee/wiretrustee-dashboard)

https://github.com/wiretrustee/wiretrustee/blob/main/docs/README.md

### Why using Wiretrustee?

* Connect multiple devices to each other via a secure peer-to-peer Wireguard VPN tunnel. At home, the office, or anywhere else.
* No need to open ports and expose public IPs on the device, routers etc.
* Uses Kernel Wireguard module if available.
* Automatic network change detection. When a new peer joins the network others are notified and keys are exchanged automatically.  
* Automatically reconnects in case of network failures or switches.
* Automatic NAT traversal.
* Relay server fallback in case of an unsuccessful peer-to-peer connection.
* Private key never leaves your device.
* Automatic IP address management.
* Intuitive UI Dashboard.
* Works on ARM devices (e.g. Raspberry Pi).
* Open-source (including Management Service)

### Secure peer-to-peer VPN in minutes
![animation](docs/media/peers.gif)

### A bit on Wiretrustee internals
* Wiretrustee features a Management Service that offers peer IP management and network updates distribution (e.g. when new peer joins the network).
* Wiretrustee uses WebRTC ICE implemented in [pion/ice library](https://github.com/pion/ice) to discover connection candidates when establishing a peer-to-peer connection between devices.
* Peers negotiate connection through [Signal Service](signal/).
* Signal Service uses public Wireguard keys to route messages between peers.
  Contents of the messages sent between peers through the signaling server are encrypted with Wireguard keys, making it impossible to inspect them.
* Occasionally, the NAT-traversal is unsuccessful due to strict NATs (e.g. mobile carrier-grade NAT).
  When this occurs the system falls back to relay server (TURN), and a secure Wireguard tunnel is established via TURN server.
  [Coturn](https://github.com/coturn/coturn) is the one that has been successfully used for STUN and TURN in Wiretrustee setups.

### Product Roadmap
- [Public Roadmap](https://github.com/wiretrustee/wiretrustee/projects/2)
- [Public Roadmap Progress Tracking](https://github.com/wiretrustee/wiretrustee/projects/1)

### Client Installation
#### Linux
1. Checkout Wiretrustee [releases](https://github.com/wiretrustee/wiretrustee/releases)   
2. Download the latest release (**Switch VERSION to the latest**):

**Debian packages**
```shell
wget https://github.com/wiretrustee/wiretrustee/releases/download/v<VERSION>/wiretrustee_<VERSION>_linux_amd64.deb
```
3. Install the package
```shell
sudo dpkg -i wiretrustee_<VERSION>_linux_amd64.deb
```
**Fedora/Centos packages**
```shell
wget https://github.com/wiretrustee/wiretrustee/releases/download/v<VERSION>/wiretrustee_<VERSION>_linux_amd64.rpm
```
3. Install the package
```shell
sudo rpm -i wiretrustee_<VERSION>_linux_amd64.rpm
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
sudo mv wiretrusee /usr/local/bin/wiretrustee
chmod +x /usr/local/bin/wiretrustee
```
After that you may need to add /usr/local/bin in your MAC's PATH environment variable:
````shell
export PATH=$PATH:/usr/local/bin
````

#### Windows
1. Checkout Wiretrustee [releases](https://github.com/wiretrustee/wiretrustee/releases/latest)
2. Download the latest Windows release installer ```wiretrustee_installer_<VERSION>_windows_amd64.exe``` (**Switch VERSION to the latest**):
3. Proceed with installation steps
4. This will install the client in the C:\\Program Files\\Wiretrustee and add the client service
5. After installing you can follow the [Client Configuration](#Client-Configuration) steps.
> To uninstall the client and service, you can use Add/Remove programs

### Client Configuration
1. Login to the Management Service. You need to have a `setup key` in hand (see ).

For **Unix** systems:
```shell
sudo wiretrustee login --setup-key <SETUP KEY>
```
For  **Windows** systems:
```shell
.\wiretrustee.exe login --setup-key <SETUP KEY>
 ```

Alternatively, if you are hosting your own Management Service provide `--management-url` property pointing to your Management Service:
```shell
sudo wiretrustee login --setup-key <SETUP KEY> --management-url https://localhost:33073
```

You could also omit `--setup-key` property. In this case the tool will prompt it the key.

2. Start Wiretrustee:

For **MACOS** you will just start the service:
````shell
sudo wiretrustee up
# or
sudo wiretrustee up & # to run it in background
````   
For **Linux** systems:
```shell
sudo systemctl restart wiretrustee.service
sudo systemctl status wiretrustee.service 
```
For **Windows** systems:
```shell
.\wiretrustee.exe service start
```
> You may need to run Powershell as Administrator

3. Check your IP:
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

4. Repeat on other machines.  

### Running Dashboard, Management, Signal and Coturn
Wiretrustee uses [Auth0](https://auth0.com) for user authentication and authorization, therefore you will need to create a free account 
and configure Auth0 variables in the compose file (dashboard) and in the management config file.
We chose Auth0 to "outsource" the user management part of our platform because we believe that implementing a proper user auth is not a trivial task and requires significant amount of time to make it right. We focused on connectivity instead.
It is worth mentioning that dependency to Auth0 is the only one that cannot be self-hosted.

Configuring Wiretrustee Auth0 integration:
- check [How to run](https://github.com/wiretrustee/wiretrustee-dashboard#how-to-run) to obtain Auth0 environment variables for UI Dashboard
- set these variables in the [environment section of the docker-compose file](https://github.com/wiretrustee/wiretrustee/blob/main/infrastructure_files/docker-compose.yml)
- check [Auth0 Golang API Guide](https://auth0.com/docs/quickstart/backend/golang) to obtain ```AuthIssuer```, ```AuthAudience```, and ```AuthKeysLocation```
- set these properties in the [management config files](https://github.com/wiretrustee/wiretrustee/blob/main/infrastructure_files/management.json#L33)


Under infrastructure_files we have a docker-compose example to run Dashboard, Wiretrustee Management and Signal services, plus an instance of [Coturn](https://github.com/coturn/coturn), it also provides a turnserver.conf file as a simple example of Coturn configuration. 
You can edit the turnserver.conf file and change its Realm setting (defaults to wiretrustee.com) to your own domain and user setting (defaults to username1:password1) to **proper credentials**.

The example is set to use the official images from Wiretrustee and Coturn, you can find our documentation to run the signal server in docker in [Running the Signal service](#running-the-signal-service), the management in [Management](./management/README.md), and the Coturn official documentation [here](https://hub.docker.com/r/coturn/coturn).

> Run Coturn at your own risk, we are just providing an example, be sure to follow security best practices and to configure proper credentials as this service can be exploited and you may face large data transfer charges.

Also, if you have an SSL certificate for Coturn, you can modify the docker-compose.yml file to point to its files in your host machine, then switch the domainname to your own SSL domain. If you don't already have an SSL certificate, you can follow [Certbot's](https://certbot.eff.org/docs/intro.html) official documentation
to generate one from [Let’s Encrypt](https://letsencrypt.org/), or, we found that the example provided by [BigBlueButton](https://docs.bigbluebutton.org/2.2/setup-turn-server.html#generating-tls-certificates) covers the basics to configure Coturn with Let's Encrypt certs. 
> The Wiretrustee Management service can generate and maintain the certificates automatically, all you need to do is run the servicein a host  with a public IP, configure a valid DNS record pointing to that IP and uncomment the 443 ports and command lines in the docker-compose.yml file.

Simple docker-composer execution:
````shell
cd infrastructure_files
docker-compose up -d
````
You can check logs by running:
````shell
cd infrastructure_files
docker-compose logs signal
docker-compose logs management
docker-compose logs coturn
````
If you need to stop the services, run the following:
````shell
cd infrastructure_files
docker-compose down
````


### Legal
 [WireGuard](https://wireguard.com/) is a registered trademark of Jason A. Donenfeld.

