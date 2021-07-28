# Wiretrustee

A WireGuard®-based mesh network that connects your devices into a single private network.

### Why using Wiretrustee?

* Connect multiple devices to each other via a secure peer-to-peer Wireguard VPN tunnel. At home, the office, or anywhere else.
* No need to open ports and expose public IPs on the device.
* Automatically reconnects in case of network failures or switches.
* Automatic NAT traversal.
* Relay server fallback in case of an unsuccessful peer-to-peer connection.
* Private key never leaves your device.
* Works on ARM devices (e.g. Raspberry Pi).

### A bit on Wiretrustee internals
* Wiretrustee uses WebRTC ICE implemented in [pion/ice library](https://github.com/pion/ice) to discover connection candidates when establishing a peer-to-peer connection between devices.
* A connection session negotiation between peers is achieved with the Wiretrustee Signalling server [signal](signal/)
* Contents of the messages sent between peers through the signaling server are encrypted with Wireguard keys, making it impossible to inspect them.
  The routing of the messages on a Signalling server is based on public Wireguard keys. 
* Occasionally, the NAT-traversal is unsuccessful due to strict NATs (e.g. mobile carrier-grade NAT).
  For that matter, there is support for a relay server fallback (TURN) and a secure Wireguard tunnel is established via TURN server.
  [Coturn](https://github.com/coturn/coturn) is the one that has been successfully used for STUN and TURN in Wiretrustee setups.

### What Wiretrustee is not doing:
* Wireguard key management. In consequence, you need to generate peer keys and specify them on Wiretrustee initialization step. This feature is on the roadmap.
* Peer address management. You have to specify a unique peer local address (e.g. 10.30.30.1/24) when configuring Wiretrustee. This feature is on the roadmap.

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
2. Download the latest Windows release ```wiretrustee_<VERSION>_windows_amd64.tar.gz``` (**Switch VERSION to the latest**):
3. Decompress and move to a more fixed path in your system
4. Open Powershell
5. For Windows systems, we can use the service command to configure Wiretrustee as a service by running the following commands in Powershell:
````shell
cd C:\path\to\wiretrustee\bin
.\wiretrustee.exe service --help
.\wiretrustee.exe service install # This will prompt for administrator permissions in order to install a new service
````
> You may need to run Powershell as Administrator
6. After installing you can follow the [Client Configuration](#Client-Configuration) steps.
7. To uninstall the service simple run the command above with the uninstall flag:
````shell
.\wiretrustee.exe service uninstall
````

### Client Configuration
1. Initialize Wiretrustee:

For **Unix** systems:
```shell
sudo wiretrustee init \
 --stunURLs stun:stun.wiretrustee.com:3468,stun:stun.l.google.com:19302 \
 --turnURLs <TURN User>:<TURN password>@turn:stun.wiretrustee.com:3468  \
 --signalAddr signal.wiretrustee.com:10000  \
 --wgLocalAddr 10.30.30.1/24  \
 --log-level info
```
For  **Windows** systems:
```shell
.\wiretrustee.exe init `
 --stunURLs stun:stun.wiretrustee.com:3468,stun:stun.l.google.com:19302 `
 --turnURLs <TURN User>:<TURN password>@turn:stun.wiretrustee.com:3468  `
 --signalAddr signal.wiretrustee.com:10000  `
 --wgLocalAddr 10.30.30.1/24  `
 --log-level info
 ```
 
It is important to mention that the ```wgLocalAddr``` parameter has to be unique across your network.
E.g. if you have Peer A with ```wgLocalAddr=10.30.30.1/24``` then another Peer B can have ```wgLocalAddr=10.30.30.2/24```

If for some reason, you already have a generated Wireguard key, you can specify it with the ```--wgKey``` parameter. 
If not specified, then a new one will be generated, and its corresponding public key will be output to the log.
A new config will be generated and stored under ```/etc/wiretrustee/config.json```

2. Add a peer to connect to.
   
For **Unix** systems:
```shell
sudo wiretrustee add-peer --allowedIPs 10.30.30.2/32 --key '<REMOTE PEER WIREUARD PUBLIC KEY>'
```
For  **Windows** systems:
```shell
.\wiretrustee.exe add-peer --allowedIPs 10.30.30.2/32 --key '<REMOTE PEER WIREUARD PUBLIC KEY>'
```
3. Restart Wiretrustee to reload changes
For **MACOS** you will just start the service:
````shell
sudo wiretrustee up --log-level info 
# or
sudo wiretrustee up --log-level info & # to run it in background
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
### Running the Signal service
After installing the application, you can run the signal using the command below:
````shell
/usr/local/bin/wiretrustee signal --log-level INFO
````
This will launch the Signal server on port 10000, in case you want to change the port, use the flag --port.
#### Docker image
We have packed the Signal server into docker image. You can pull the image from Docker Hub and execute it with the following commands:
````shell
docker pull wiretrustee/wiretrustee:signal-latest
docker run -d --name wiretrustee-signal -p 10000:10000 wiretrustee/wiretrustee:signal-latest
````
The default log-level is set to INFO, if you need you can change it using by updating the docker cmd as followed:
````shell
docker run -d --name wiretrustee-signal -p 10000:10000 wiretrustee/wiretrustee:signal-latest --log-level DEBUG
````

### Running Management, Signal and Coturn
Under infrastructure_files we have a docker-compose example to run both, Wiretrustee Management and Signal services, plus an instance of [Coturn](https://github.com/coturn/coturn), it also provides a turnserver.conf file as a simple example of Coturn configuration. 
You can edit the turnserver.conf file and change its Realm setting (defaults to wiretrustee.com) to your own domain and user setting (defaults to username1:password1) to **proper credentials**.

The example is set to use the official images from Wiretrustee and Coturn, you can find our documentation to run the signal server in docker in [Running the Signal service](#Running the Signal service), the management in [Management](./management/README.md), and the Coturn official documentation [here](https://hub.docker.com/r/coturn/coturn).

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

