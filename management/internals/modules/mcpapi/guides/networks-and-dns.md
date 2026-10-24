# Networks and DNS

## Choose the setup
- Networks: default for hosts, subnets and domains without NetBird (VPN-to-site, site-to-site). Nothing is reachable until a policy allows it.
- `create_route`: only exit nodes (`0.0.0.0/0`) and site-to-site that must keep source IPs. A route without `access_control_groups` grants unrestricted access.
- Policy alone: the target runs NetBird and is reached at its NetBird IP.

## Prerequisites
- Routing peer: any NetBird client (Docker needs `NET_ADMIN`) with direct reach to the resources, enrolled with a `create_setup_key` key (`auto_groups`: its group) so login expiration does not apply.
- Groups (`create_group`) for sources, routing peers, resources. `list_peers` shows `connected`, `os`, `version`.

## Build a network
1. `create_network` `{"name":"Berlin Office"}`.
2. `create_network_resource` `{"network_id":"<id>","name":"Wiki","address":"10.10.0.5/32","groups":["<res_group>"],"enabled":true}`
   - IP or `/32` is `host`, CIDR `subnet`, `app.corp.local` or `*.corp.local` `domain`.
   - `name` is unique account-wide. Send `enabled: true`; omitted means disabled.
   - A domain matches that exact name; `*.corp.local` only subdomains, so add `corp.local` separately.
3. `create_network_router` `{"network_id":"<id>","peer":"<peer_id>","metric":100,"masquerade":true,"enabled":true}`
   - Exactly one of `peer` or `peer_groups` (group IDs). `metric` 1-9999, lowest wins. Create always enables the router.
   - HA: one router per peer. Different metrics give primary/failover; equal metrics let each client pick direct over relayed, then latency. `peer_groups` members share one metric. No load balancing: build identical networks (distinct resource names), one per client group.
   - Send `masquerade`; omitted means `false`. Only Linux peers can disable it; then use different metrics and route `settings.network_range` (`get_account`) back via the active routing peer's LAN IP. Site-to-site over Networks needs `true`.
4. `create_policy` `{"name":"Dev to apps","enabled":true,"rules":[{"name":"https","enabled":true,"action":"accept","bidirectional":false,"protocol":"tcp","ports":["443"],"sources":["<dev_group>"],"destinations":["<res_group>"]}]}`
   - Or `"destinationResource":{"id":"<resource_id>","type":"<its type>"}` instead of `destinations`, never both. Resources are not in `All`; a resource without a policy is routed to no one.
   - `ports` are strings, not allowed with `all` or `icmp`. Rules to resources are one-way.
5. Services on the routing peer (SSH, SMB) need a rule to `["<routing_group>"]` on the port. At its LAN IP they also need a resource for that IP with a rule from the same sources and, on Windows, macOS or Linux netstack, client env `NB_ENABLE_LOCAL_FORWARDING=true`. ICMP needs its own rule; test with TCP.

Two networks routing one CIDR to a client: it uses one. Install NetBird on the target, renumber, or `netbird networks select`.

## DNS for domain resources
- `settings.routing_peer_dns_resolution_enabled` true (default; clients v0.35+, after restart): the routing peer resolves domain resources, so it must resolve the name, else distribute a match-domain nameserver group to its group. When false, clients resolve it themselves and need a nameserver.
- Put domain resources in their own network: a domain resolving into a subnet resource's CIDR there falls under both policies.
- Forwarder port 22054 once every peer runs v0.59.0+, else 5353. Avoid clients 0.59.0-0.59.1 with routing peers 0.59.0-0.59.9.
- Active Directory needs SRV records: a nameserver group for the AD domain pointing at the reachable DC, distributed to domain-joined clients. Avoid a DC as routing peer, else add its group to `disabled_management_groups`.

## Nameserver groups
`create_nameserver_group` `{"name":"Corp","description":"","nameservers":[{"ip":"10.0.0.10","ns_type":"udp","port":53}],"enabled":true,"groups":["<id>"],"primary":false,"domains":["corp.local"],"search_domains_enabled":true}`
- All fields required. `name` 1-40 chars, unique; 1-3 nameservers; `ns_type` `udp`; `groups` non-empty.
- Primary: `primary: true`, `domains: []`, `search_domains_enabled: false`. Match: `primary: false` plus domains, no wildcards (`corp.local` covers subdomains); most specific wins.
- One primary per peer. Add it as a second group with the same servers; never empty a match group's domains (search domains go too). Create a new primary before deleting the old.
- DNS server behind a routing peer: `/32` resource plus `udp` port `53` rule.
- Match domains work only on macOS, Windows 10+, Linux with systemd-resolved.

## Zones and records
- `create_dns_zone` `{"name":"Internal","domain":"netbird.internal","distribution_groups":["<id>"],"enable_search_domain":true}`. `domain`: unique, no wildcard, immutable, not the peer DNS domain (`settings.dns_domain`, default `netbird.cloud`/`netbird.selfhosted`).
- `create_dns_record` `{"zone_id":"<id>","name":"db.netbird.internal","type":"A","content":"192.168.0.68","ttl":300}`. `name` is the full FQDN. `A` IPv4, `AAAA` IPv6, `CNAME` domain. A CNAME shares its name with no other record; duplicates are rejected.
- Empty zones are not distributed. A zone beats a nameserver with the same domain.
- Route record targets with IP resources, or domain resources plus the routing peer's group in `distribution_groups`.

## Settings and labels
- `update_dns_settings` `{"disabled_management_groups":[...]}` replaces the list; those peers ignore nameservers and zones.
- Extra DNS labels: `create_setup_key` with `allow_extra_dns_labels: true`, client flag `--extra-dns-labels`; `get_peer` shows `extra_dns_labels`.

## Updates
`update_*` replaces the object: `get_*` first, send every field. Resource `groups` come back as objects; send `id`s. `update_dns_zone` without `enabled` re-enables it. `update_group` without `peers`/`resources` empties them. `update_account` resets omitted settings.

## Verify
- `get_network` (`routers`, `resources`, `policies`), `list_network_resources`, `list_network_routers`, `get_peer` (`connected`).
- Which networks a peer routes for: `list_all_network_routers`, then match the router IDs against `list_networks` `routers`.
- `list_nameserver_groups`, `list_dns_zones` (`records`), `get_dns_settings`.
- Client: `netbird networks ls`, `netbird status -d`, `nslookup -port=22054 <domain> <router NetBird IP>`. A domain route appears after the system resolver looks the name up.
