# Exit nodes

An exit node is a route with `network: "0.0.0.0/0"` served by a routing peer; peers in its distribution groups send all internet traffic through it. Build it with `create_route`; per the docs Networks has no exit node support.

## Prerequisites
1. Routing peer: always-on, enrolled with a setup key. Linux is preferred (kernel data path); Windows, macOS, FreeBSD, Android and tvOS forward in userspace; Docker needs `NET_ADMIN`. `get_peer`: `connected: true`, `version` 0.27.0+, `local_flags.disable_server_routes` not true.
2. A group with the routing peer(s), e.g. `exit-nodes` (`create_group`: `name`, `peers`).
3. A dedicated distribution group for full-tunnel devices, e.g. `remote-workers`, not All.
4. Clients: 0.27.0+; 0.55.0+ for auto-apply; 0.71.0+ on both ends for IPv6.

## Steps
1. `list_groups` to get group IDs.
2. `create_policy`. The route reaches only peers a policy connects to the routing peer. Documented minimum, one direction:
```json
{"name":"remote-workers to exit-nodes","enabled":true,"rules":[{"name":"exit","enabled":true,"action":"accept","bidirectional":false,"protocol":"icmp","sources":["<remote-workers>"],"destinations":["<exit-nodes>"]}]}
```
Protocol `all` also works but opens every port on the exit node host. `all` and `icmp` reject ports.
3. `create_route`:
```json
{"network_id":"exit-eu","description":"EU exit","network":"0.0.0.0/0","peer_groups":["<exit-nodes>"],"groups":["<remote-workers>"],"metric":9999,"masquerade":true,"enabled":true,"keep_route":true,"skip_auto_apply":false}
```
- Required: `network_id` (1-40 chars; clients list and select the exit node by it), `description`, `enabled`, `groups`, `keep_route` (domain routes only), `masquerade`, `metric` (1-9999, lower wins).
- `groups`: non-empty distribution groups (who uses it), not routing peers.
- Exactly one of `peer` (peer ID) or `peer_groups`; exactly one of `network` or `domains`.
- `masquerade: true`: required in practice; only Linux routing peers can turn it off.
- `skip_auto_apply`: `false` (default) activates it on clients at once; `true` only offers it in the client's exit node selector. A user's own choice always wins.
- `access_control_groups`: leave unset. When set, routed traffic needs a policy with that group as destination, else all of it drops.
4. DNS, the dashboard's match domain ALL: `create_nameserver_group` with `{"name":"exit-dns","description":"","nameservers":[{"ip":"1.1.1.1","ns_type":"udp","port":53}],"groups":["<remote-workers>"],"primary":true,"domains":[],"search_domains_enabled":false,"enabled":true}`. Avoids DNS location leaks and unreachable local resolvers.
5. IPv6: add no `::/0` route. Management adds `::/0` for 0.71.0+ peers holding an IPv6 overlay address (`get_peer` `ipv6`; groups in `get_account` `settings.ipv6_enabled_groups`); other peers get IPv6 blocked.

## HA and regions
- One exit node, several routing peers: one route with `peer_groups` (members share the metric), or several routes with the same `network_id`, `network` and `groups`, each with its own `peer` and `metric`. Use one `skip_auto_apply` value on all entries: any `false` entry auto-applies it.
- Equal metrics: a client prefers direct over relayed, then lowest latency. Different metrics: primary/failover with failback. With masquerade every switch resets TCP connections.
- Separate exit nodes (different `network_id`) give no failover: a client auto-applies only the alphabetically first `network_id` and keeps it while its peer is offline. Keep at most one auto-applied exit node per device; offer others with `skip_auto_apply: true`.
- Do not reuse a routing peer across two `0.0.0.0/0` routes. The server rejects a peer group, or its member, already serving it ("already has this route", HTTP 409), but not a peer reused via `peer`; check `list_routes`.

## Location gating
`create_posture_check` with `checks.geo_location_check` `{"action":"deny","locations":[{"country_code":"US"}]}` or `checks.peer_network_range_check` `{"action":"deny","ranges":["192.168.1.0/24"]}` (office subnet). A peer matching a `deny` check loses the exit node. Put its ID in the exit policy's `source_posture_checks`, never via the route's `access_control_groups` (route still installs, device loses internet). That policy must be the only one linking the two groups. To add it later: `get_policy`, turn rule `sources`/`destinations` objects into ID strings, `update_policy`.

## Updating
`update_route` replaces the route. Start from `get_route`, pass `route_id`, drop `id` and `network_type`, then:
- drop `peer` when it is `""` and `peer_groups` is set, and drop `domains`; both fields of either pair fail with HTTP 422;
- resend `skip_auto_apply` and `access_control_groups`, or they reset to false and empty.

## Verify
- `get_route`: `network` `0.0.0.0/0`, `network_type` `IPv4`, `enabled`, `masquerade`, `groups`, `skip_auto_apply`.
- `list_accessible_peers` with a client `peer_id`: the routing peer must appear.
- `get_peer`: routing peer `connected`; client `local_flags.disable_client_routes` not true.
- `list_nameserver_groups`: primary group on the distribution group.
- On a device: `netbird networks ls`, `netbird status -d`, public IP = exit node's.

## Pitfalls
- `0.0.0.0/0` reaches all the exit node can reach, its LAN included. Use an internet-only segment, plus Block LAN access on the exit node peer (`netbird down`, then `netbird up --block-lan-access`; read-only `local_flags.block_lan_access`), which breaks LAN routes that peer serves. Host firewall rules there do not filter tunneled traffic.
- Serve internal resources from another routing peer via Networks (specific routes beat `0.0.0.0/0`). Never use one routing peer for both Routes and Networks: permissions leak.
- Auto-apply is not a lock; locking needs the device's `disableNetworks` MDM key (0.73.0+) or `--disable-networks` (0.69.0+), deployed before users deselect.
- Cannot use exit nodes: MikroTik RouterOS containers, clients with `NB_DISABLE_CUSTOM_ROUTING` or `disable_client_routes`.
- Per-device throughput is capped at one tunnel on one CPU core.
