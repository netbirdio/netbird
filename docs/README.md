## Introduction

Wiretrustee is an open-source VPN platform built on top of [Wireguard](https://www.wireguard.com/) making it easy to create secure private networks for your organization or home.

It requires zero configuration effort leaving behind the hassle of opening ports, complex firewall rules, vpn gateways, and so forth.

There is no centralized VPN server with Wiretrustee - your computers, devices, machines, and servers connect to each other directly over a fast encrypted tunnel.

It literally takes less than 5 minutes to provision a secure peer-to-peer VPN with Wiretrustee. Check our [Quickstart Guide Video](https://www.youtube.com/watch?v=cWTsGUJAUaU) to see the setup in action.

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

