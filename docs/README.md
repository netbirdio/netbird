### Table of contents

* [About Wiretrustee](#about-wiretrustee)
* [Why Wireguard with Wiretrustee?](#why-wireguard-with-wiretrustee)
* [Wiretrustee vs. Traditional VPN](#wiretrustee-vs-traditional-vpn)
* [High-level technology overview](#high-level-technology-overview)
* [Getting started](#getting-started)

### About Wiretrustee

Wiretrustee is an open-source VPN platform built on top of [WireGuard®](https://www.wireguard.com/) making it easy to create secure private networks for your organization or home.

It requires zero configuration effort leaving behind the hassle of opening ports, complex firewall rules, vpn gateways, and so forth.

There is no centralized VPN server with Wiretrustee - your computers, devices, machines, and servers connect to each other directly over a fast encrypted tunnel.

It literally takes less than 5 minutes to provision a secure peer-to-peer VPN with Wiretrustee. Check our [Quickstart Guide Video](https://www.youtube.com/watch?v=cWTsGUJAUaU) to see the setup in action.

### Why Wireguard with Wiretrustee?

WireGuard is a modern and extremely fast VPN tunnel utilizing state-of-the-art [cryptography](https://www.wireguard.com/protocol/)
and Wiretrustee uses Wireguard to establish a secure tunnel between machines.

Built with simplicity in mind, Wireguard ensures that traffic between two machines is encrypted and flowing, however, it requires a few things to be done beforehand.

First, in order to connect, the machines have to be configured.
On each machine, you need to generate private and public keys and prepare a WireGuard configuration file.
The configuration also includes a private IP address that should be unique per machine.

Secondly, to accept the incoming traffic, the machines have to trust each other.
The generated public keys have to be pre-shared on the machines.
This works similarly to SSH with its authorised_keys file.

Lastly, the connectivity between the machines has to be ensured.
To make machines reach one another, you are required to set a WireGuard endpoint property which indicates the IP address and port of the remote machine to connect to.
On many occasions, machines are hidden behind firewalls and NAT devices,
meaning that you may need to configure a port forwarding or open holes in your firewall to ensure the machines are reachable.

The undertakings mentioned above might not be complicated if you have just a few machines, but the complexity grows as the number of machines increases.

Wiretrustee simplifies the setup by automatically generating private and public keys, assigning unique private IP addresses, and takes care of sharing public keys between the machines.
It is worth mentioning that the private key never leaves the machine.
So only the machine that owns the key can decrypt traffic addressed to it.
The same applies also to the relayed traffic mentioned below.

Furthermore, Wiretrustee ensures connectivity by leveraging advanced [NAT traversal techniques](https://en.wikipedia.org/wiki/NAT_traversal)
and removing the necessity of port forwarding, opening holes in the firewall, and having a public static IP address.  
In cases when a direct peer-to-peer connection isn't possible, all traffic is relayed securely between peers.
Wiretrustee also monitors the connection health and restarts broken connections.

There are a few more things that we are working on to make secure private networks simple. A few examples are ACLs, MFA and activity monitoring.

Check out the WireGuard [Quick Start](https://www.wireguard.com/quickstart/) guide to learn more about configuring "plain" WireGuard without Wiretrustee.

### Wiretrustee vs. Traditional VPN

In the traditional VPN model, everything converges on a centralized, protected network where all the clients are connecting to a central VPN server.

An increasing amount of connections can easily overload the VPN server.
Even a short downtime of a server can cause expensive system disruptions, and a remote team's inability to work.

Centralized VPNs imply all the traffic going through the central server causing network delays and increased traffic usage.

Such systems require an experienced team to set up and maintain.
Configuring firewalls, setting up NATs, SSO integration, and managing access control lists can be a nightmare.

Traditional centralized VPNs are often compared to a [castle-and-moat](https://en.wikipedia.org/wiki/Moat) model
in which once accessed, user is trusted and can access critical infrastructure and resources without any restrictions.

Wiretrustee decentralizes networks using direct point-to-point connections, as opposed to traditional models.
Consequently, network performance is increased since traffic flows directly between the machines bypassing VPN servers or gateways.
To achieve this, Wiretrustee client applications employ signalling servers to find other machines and negotiate connections.
These are similar to the signaling servers used in [WebRTC](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Signaling_and_video_calling#the_signaling_server)

Thanks to [NAT traversal techniques](https://en.wikipedia.org/wiki/NAT_traversal),
outlined in the [Why not just Wireguard?](#why-wireguard-with-wiretrustee) section above,
Wiretrustee installation doesn't require complex network and firewall configuration.
It just works, minimising the maintenance effort.

Finally, each machine or device in the Wiretrustee network verifies incoming connections accepting only the trusted ones.
This is ensured by Wireguard's [Crypto Routing concept](https://www.wireguard.com/#cryptokey-routing).

### High-level technology overview
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