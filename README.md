# Wiretrustee

A WireGuard®-based mesh network that connects your devices into a single private network.

### Why using Wiretrustee?

* Connect multiple devices at home, office or anywhere else to each other via a secure peer-to-peer Wireguard VPN tunnel.
* No need to open ports and expose public IPs on the device.
* Automatic reconnects in case of network failures or switches. 
* Automatic NAT traversal.
* Relay server fallback in case of an unsuccessful peer-to-peer connection. 
* Private key never leaves your device.
* Works on ARM devices (e.g. Raspberry Pi).

### A bit on Wiretrustee internals
* Wiretrustee uses WebRTC ICE implemented in [pion/ice library](https://github.com/pion/ice) to discover connection candidates 
when establishing a peer-to-peer connection between devices.
* A connection session negotiation between peers is achieved with Wiretrustee Signalling server [signal](signal/)
* Contents of the messages sent between peers through the signalling server are encrypted with Wireguard keys making it impossible
  to inspect them. 
  The routing of the messages on a Signalling server is based on public Wireguard keys. 
* Sometimes NAT-traversal is unsuccessful due to strict NATs (e.g. mobile carrier grade NAT).  
For that matter there is a support for a relay server fallback (TURN). In this case a secure Wireguard tunnel is established via a TURN server.
  [Coturn](https://github.com/coturn/coturn) is the one that has been successfully used for STUN and TURN in Wiretrustee setups.

### What Wiretrustee is not doing (yet):
* Wireguard key management. For that reason you need to generate peer keys and specify them on Wiretrustee initialization step.
However, the support for the key management feature is in our roadmap.
* Peer address assignment. You have to specify a unique peer local address (e.g. 10.30.30.1/24) when configuring Wiretrustee 
  Same as for the key management it is in our roadmap.

### Installation
1. Checkout Wiretrustee releases
   https://github.com/wiretrustee/wiretrustee/releases
2. Download the latest release:
```shell
wget https://github.com/wiretrustee/wiretrustee/releases/download/v0.0.4/wiretrustee_0.0.4_linux_amd64.rpm
```
3. Install the package
```shell
sudo dpkg -i wiretrustee_0.0.4_linux_amd64.rpm
```
4. Initialize Wiretrustee:
```shell
sudo wiretrustee init \
 --stunURLs stun:stun.wiretrustee.com:3468,stun:stun.l.google.com:19302 \
 --turnURLs <TURN User>:<TURN password>@turn:stun.wiretrustee.com:3468  \
 --signalAddr signal.wiretrustee.com:10000  \
 --wgLocalAddr 10.30.30.1/24  \
 --log-level info
```
It is important to mention that ```wgLocalAddr``` parameter has to be unique across your network 
E.g. if you have a Peer A with wgLocalAddr=10.30.30.1/24 then another Peer B can have a wgLocalAddr=10.30.30.2/24

If for some reason you already have a generated Wireguard key you can specify it with ```--wgKey``` parameter.
If not specified then a new one will be generated, and it's corresponding public key will be output in the log.

A new config will be generated and stored under ```/etc/wiretrustee/config.json```

5. Add a peer to connect to. 
```
sudo wiretrustee add-peer --allowedIPs 10.30.30.2/32 --key '<REMOTE PEER WIREUARD PUBLIC KEY>'
```

###Roadmap
* Android app
* Key and address management service with SSO 