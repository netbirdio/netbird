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
* Wireguard key management. In consequence, you need to generate peer keys and specify them on Wiretrustee initialization step.
* Peer address management. You have to specify a unique peer local address (e.g. 10.30.30.1/24) when configuring Wiretrustee

### Client Installation
#### Linux
1. Checkout Wiretrustee [releases](https://github.com/wiretrustee/wiretrustee/releases)   
2. Download the latest release (**Switch VERSION to the lates**):

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
2. Download the latest release (**Switch VERSION to the lates**):
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
### Client Configuration
1. Initialize Wiretrustee:

For **MACOS**, you need to create the configuration directory:
````shell
sudo mkdir /etc/wiretrustee
````
Then, for all systems:
```shell
sudo wiretrustee init \
 --stunURLs stun:stun.wiretrustee.com:3468,stun:stun.l.google.com:19302 \
 --turnURLs <TURN User>:<TURN password>@turn:stun.wiretrustee.com:3468  \
 --signalAddr signal.wiretrustee.com:10000  \
 --wgLocalAddr 10.30.30.1/24  \
 --log-level info
```
It is important to mention that the ```wgLocalAddr``` parameter has to be unique across your network.
E.g. if you have Peer A with ```wgLocalAddr=10.30.30.1/24``` then another Peer B can have ```wgLocalAddr=10.30.30.2/24```

If for some reason, you already have a generated Wireguard key, you can specify it with the ```--wgKey``` parameter. 
If not specified, then a new one will be generated, and its corresponding public key will be output to the log.
A new config will be generated and stored under ```/etc/wiretrustee/config.json```

2. Add a peer to connect to. 
```shell
sudo wiretrustee add-peer --allowedIPs 10.30.30.2/32 --key '<REMOTE PEER WIREUARD PUBLIC KEY>'
```

3. Restart Wiretrustee to reload changes
For **MACOS** you will just start the service:
````shell
sudo wiretrustee up --log-level info 
# or
sudo wiretrustee up --log-level info & # for run it in background
````   
For **Linux** systems:
```shell
sudo systemctl restart wiretrustee.service
sudo systemctl status wiretrustee.service 
```
### Running the Signal service
After installing the application, you can run the signal using the command below:
````shell
/usr/local/bin/wiretrustee signal --log-level INFO
````
This will launch the signal service on port 10000, in case you want to change the port, use the flag --port.
#### Docker image
We have packed the signal into docker images. You can pull the images from the Docker Hub and execute it with the following commands:
````shell
docker pull wiretrustee/wiretrustee:signal-latest
docker run -d --name wiretrustee-signal -p 10000:10000 wiretrustee/wiretrustee:signal-latest
````
The default log-level is set to INFO, if you need you can change it using by updating the docker cmd as followed:
````shell
docker run -d --name wiretrustee-signal -p 10000:10000 wiretrustee/wiretrustee:signal-latest --log-level DEBUG
````

### Running Signal and Coturn
Under infrastructure_files we have a docker-compose example to run both, Wiretrustee signal server and an instance of [Coturn](https://github.com/coturn/coturn), it also provides a turnserver.conf file as a simple example of Coturn configuration. 
You can edit the turnserver.conf file and change its Realm (default to wiretrustee.com) setting to your own domain and the user (defaults to username1:password1) setting to **proper credentials**.

The example is set to use the official images from Wiretrustee and Coturn, you can find our documentation to run the signal server in docker in [Running the Signal service](#Running the Signal service) and the Coturn official documentation [here](https://hub.docker.com/r/coturn/coturn).

> Run Coturn at you own risk, we are just providing an example, be sure to follow security best practices and to configure proper credentials as this service can be exploited and you may face large data transfer charges.

Also, if you have a SSL certificate you can modify the docker-compose.yml file to point to its files in your host machine, then switch the domainname to your own SSL domain. If you don't already have a SLL certificate, you can follow [Certbot's](https://certbot.eff.org/docs/intro.html) official documentation
to generate one from [Let’s Encrypt](https://letsencrypt.org/), or, we found that the example provided by [BigBlueButton](https://docs.bigbluebutton.org/2.2/setup-turn-server.html#generating-tls-certificates) covers the basics to configure Coturn with Let's Encrypt certs. 

Simple docker-composer execution:
````shell
cd infrastructure_files
docker-compose up -d
````
You can check logs by running:
````shell
cd infrastructure_files
docker-compose logs signal
docker-compose logs coturn
````
If you need to stop the services, run the following:
````shell
cd infrastructure_files
docker-compose down
````
### Roadmap
* Android app
 
