### Table of contents

* [About Wiretrustee](#about-wiretrustee)
* [Why not just Wireguard?](#why-not-just-wireguard)
* [High-level technology overview](#high-level-overview)
* [Getting started](#getting-started)

### About Wiretrustee

Wiretrustee is an open-source VPN platform built on top of [WireGuard®](https://www.wireguard.com/) making it easy to create secure private networks for your organization or home.

It requires zero configuration effort leaving behind the hassle of opening ports, complex firewall rules, vpn gateways, and so forth.

There is no centralized VPN server with Wiretrustee - your computers, devices, machines, and servers connect to each other directly over a fast encrypted tunnel.

It literally takes less than 5 minutes to provision a secure peer-to-peer VPN with Wiretrustee. Check our [Quickstart Guide Video](https://www.youtube.com/watch?v=cWTsGUJAUaU) to see the setup in action.

### Why not just Wireguard?

WireGuard is a modern, and extremely fast VPN tunnel utilizing state-of-the-art [cryptography](https://www.wireguard.com/protocol/) and Wiretrustee uses Wireguard to establish a secure tunnel between machines.

Built with the simplicity in mind Wireguard ensures that traffic between two machines is encrypted and flowing, however it requires a few things to be done beforehand.

First, in order to connect, the machines have to be configured.
On each machine you need to generate private and public keys and prepare a WireGuard configuration file. 
Configuration also includes a private IP address that should be unique per machine.

Second, to accept the incoming traffic the machines have to trust each other. 
The generated public keys have to be pre-shared on the machines. It works similar to SSH with it's authorised_keys file. 

Third, the connectivity between the machines has to be ensured.
For machines to reach each other a WireGuard endpoint property has to be set which indicates the IP address and port of the remote machine to connect to.
Quite often machines are hidden behind firewalls and NAT devices meaning that you may need to configure port forwarding or open holes in your firewall to ensure the machines are reachable.
 
All the things above might not be a problem when you have just a few machines, but the complexity grows when the number of machines increases.

Wiretrustee simplifies the setup by automatically generating private and public keys, assigning unique private IP addresses,
and takes care of sharing public keys between the machines.
It is worth mentioning that private key never leaves the machine - only this machine can decrypt traffic that is address to it.

Additionally, Wiretrustee ensures connectivity by leveraging advanced [NAT traversal techniques](https://en.wikipedia.org/wiki/NAT_traversal) 
and removing the necessity of opening holes in the firewall, port forwarding, and having a public static IP address.  
In cases when a direct peer-to-peer connection isn't possible the connection the traffic is relayed securely between peers.
Wiretrustee also monitors the connection health and restarts broken connections.

There are a few more things that we are working on to make secure private networks simple. A few examples are ACLs, MFA and activity monitoring.

Check out the WireGuard [Quick Start](https://www.wireguard.com/quickstart/) guide to learn more about configuring "plain" WireGuard without Wiretrustee.

### High-level overview
In essence, Wiretrustee is an open source platform consisting of a collection of systems, responsible for handling peer-to-peer connections, tunneling and network management (IP, keys, ACLs, etc).

<p align="center">
    <img src="media/high-level-dia.png" alt="high-level-dia" width="781"/>
</p>

Wiretrustee uses open-source technologies like [WireGuard®](https://www.wireguard.com/), [Pion ICE (WebRTC)](https://github.com/pion/ice), [Coturn](https://github.com/coturn/coturn),
and [software](https://github.com/wiretrustee/wiretrustee) developed by Wiretrustee authors to make it all work together.

To learn more about Wiretrustee architecture, please refer to the [architecture section](../docs/architecture.md).

### Getting Started

There are 2 ways of getting started with Wiretrustee:
- use Cloud Managed version
- self-hosting

We recommend starting with the cloud managed version hosted at [app.wiretrustee.com](https://app.wiretrustee.com) - the quickest way to get familiar with the system.
See [Quickstart Guide](../docs/quickstart.md) for instructions.

If you don't want to use the managed version, check out our [Self-hosting Guide](../docs/self-hosting.md).

