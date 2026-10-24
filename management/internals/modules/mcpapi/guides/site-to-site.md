# Site-to-site and site-to-VPN

## Pick the approach
- **Networks (default).** Each site is a Network (subnet resource, routers, a policy per resource), deny by default. Needs `masquerade: true` on both sides; the destination sees its local routing peer's LAN IP.
- **Routes (`create_route`, deprecated in the docs).** Only when source IPs must survive end to end (`masquerade: false`) or traffic must flow without policy gating (no `access_control_groups`). Never mix Routes and Networks on one routing peer: the route bypasses resource policies.

## Prerequisites
- One always-on **Linux** routing peer per site (only Linux does the needed outbound SNAT). In `list_peers` check `os`, `connected`, `groups`, and that `local_flags` `disable_server_routes`, `disable_client_routes`, `block_inbound`, `block_lan_access` are false.
- Groups (`create_group {"name":...}` returns the `id`; `list_groups {"name":...}` finds one): peer groups `site-a-routers`, `site-b-routers`; resource-only `site-a-cidr`, `site-b-cidr`.
- Enroll: `create_setup_key {"name":"Site A","type":"one-off","expires_in":86400,"usage_limit":1,"auto_groups":["<site-a-routers id>"]}`, then `netbird up --setup-key <key>`. Enrolled peer: `update_group` with every current peer ID (from `get_group`) plus it.

## Networks (repeat per site, swap A/B)
1. `create_network {"name":"site-a"}`.
2. `create_network_resource {"network_id":"<id>","name":"site-a-subnet","address":"10.0.0.0/24","enabled":true,"groups":["<site-a-cidr id>"]}`. `name` is unique per account.
3. `create_network_router {"network_id":"<id>","peer_groups":["<site-a-routers id>"],"masquerade":true,"metric":9999,"enabled":true}`. Exactly one of `peer`/`peer_groups`; existence is not checked.
4. `create_policy`, one per direction, one rule each:
```json
{"name":"B to A","enabled":true,"rules":[{"name":"B to A","enabled":true,"action":"accept","bidirectional":false,"protocol":"all","sources":["<site-b-routers id>"],"destinations":["<site-a-cidr id>"]}]}
```
Mirror it: `site-a-routers` to `site-b-cidr`. A resource without an enabled policy is not routed. Narrow with `tcp`/`udp` plus `ports` or `port_ranges` (not with `all`/`icmp`).
5. Outside NetBird: each LAN gateway routes the remote subnet via the local routing peer's LAN IP (`get_peer` `network_addresses`). Cloud: AWS source/dest check off or GCP/Azure IP forwarding on, VPC route to the routing peer, security groups allowing it.

## Routes
`create_route` per site. `network_id` is the route's own label (1 to 40 chars), not a Network ID.
```json
{"network_id":"site-a","description":"Site A","network":"10.0.0.0/24","peer_groups":["<site-a-routers id>"],"groups":["<site-b-routers id>"],"access_control_groups":["<site-a-routers id>"],"masquerade":true,"metric":9999,"enabled":true,"keep_route":true}
```
Swap for site B. Add policies `site-a-routers` to `site-b-routers` and the reverse (`protocol: all`); a route reaches only peers with a policy to its routing peer. With `access_control_groups`, policy sources must also be in the route's `groups`. With `masquerade: false` leave `access_control_groups` empty: route ACLs match NetBird IPs only, so LAN sources are dropped. Without ACL groups the whole range is open.

## Masquerade off (source IP visibility)
Linux only; breaks Networks site-to-site. `get_network_router`, then `update_network_router` with `network_id`, `router_id`, the same `peer` or `peer_groups`, `metric`, `enabled`, and `masquerade:false`. Return route for the account range (`get_account` `settings.network_range`, normally a /16, not 100.64.0.0/10) via the routing peer's LAN IP on the destination host or its gateway. Restrict with policy ports.

## High availability
Routers in one `peer_groups` entry share a metric; for primary/failover add each by `peer` with its own metric (lower wins), in separate failure domains. With masquerade on, a switch resets TCP; with it off, the return route must follow the active peer (VRRP virtual IP), never two equal-cost routes.

## Site-to-VPN (clientless site device connects to a NetBird peer)
1. Network, site CIDR resource and router as in Networks steps 1 to 3. `masquerade` does not cover this direction.
2. `create_policy`: `sources` the site router group, `destinations` the target peer group, e.g. `"protocol":"tcp","ports":["8080"]`.
3. Outside NetBird, any OS: SNAT on the routing peer (Linux: `iptables -t nat -A POSTROUTING -s <site CIDR> -o wt0 -j MASQUERADE`, persisted; others: native NAT), `ip_forward` 1, and a site route for the account range via the routing peer (static or DHCP option 121). NetBird names need a forwarder (dnsmasq) on the routing peer.

## Overlapping subnets (sites need different subnets)
- Routes: same `network_id` and `network` on different peers is one HA route; a peer may serve a prefix in one route only. Different IDs, same CIDR: users pick with `netbird routes select` (client 0.27.4+).
- Networks: two resources with one CIDR reach only one site; NETMAP remapping is not supportable. Fixes, in order: client on the device, one site at a time (`netbird networks select`), renumber, or a TCP proxy on each routing peer's NetBird IP plus a peer policy to its group on that port.

## Verify
- `get_network`: `routing_peers_count` > 0 (counts offline peers), `policies` not empty; `list_network_routers`: `masquerade`, `metric`, `enabled`; `list_peers`: routers `connected`.
- `get_policy`: `sources`/`destinations` not empty (unknown group IDs are dropped silently).
- `list_accessible_peers {"peer_id":"<site A router>"}` lists the site B routers, and the reverse.
- Hosts: ping both ways (needs `all` or `icmp`), `netbird networks ls`.

## Update pitfalls
- `update_*` replaces the object: send group IDs, not objects; omit the object's `id`, `type`, `network_type`.
- `get_route` returns `peer:""` beside `peer_groups`, and `network:"192.0.2.0/32"` beside `domains`: drop the unused field or `update_route` fails.
- `update_policy`: keep rule `id`; omit `destinations` when using `destinationResource` (`[]` counts). One rule per policy: `get_policy` can drop a later rule's sources and an update saves that.
- Keep domain and IP-range resources in separate networks (their policies overlap).
