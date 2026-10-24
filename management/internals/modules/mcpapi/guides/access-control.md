# Access control: policies, posture checks, SSH

NetBird denies all traffic unless an enabled policy allows it.

## Argument rules
- Send exactly one object in `rules` (a second collides on the rule ID); one policy per flow.
- Use IDs from `list_groups`/`list_posture_checks`, never names. Unknown IDs are dropped silently; compare the response's groups and `source_posture_checks` with the request.
- Rule: `name`, `enabled`, `action` `accept` (spec also allows `drop`; docs say allow-only), `bidirectional`, `protocol` (`all`, `tcp`, `udp`, `icmp`, `netbird-ssh`), `ports` (strings "1"-"65535") or `port_ranges` (`[{"start":8000,"end":8090}]`), never both; to mix, send single ports as ranges with `start` = `end`. No ports with `all`/`icmp`; `tcp`/`udp`/`netbird-ssh` without ports opens every port. Ranges need client 0.48+.
- Each side takes groups (`sources`, `destinations`) or one resource (`sourceResource`, `destinationResource` = `{"id","type"}`). Omit the unused key, including a `null` from `get_policy`; never send `[]`. Type `peer` takes a `list_peers` ID; `host`/`subnet`/`domain` a `list_network_resources` ID (destination only).
- `update_policy` (`policy_id` + full body) replaces everything: `get_policy` first, keep the rule `id`, turn group objects into ID strings, resend `description`, ports and `source_posture_checks` (omitting it detaches all checks).

## Least-privilege policy
```json
{"name":"eng-users -> prod-db [TCP/5432]","enabled":true,
 "rules":[{"name":"eng-users -> prod-db","enabled":true,"action":"accept",
  "bidirectional":false,"protocol":"tcp","ports":["5432"],
  "sources":["<eng-users id>"],"destinations":["<prod-db id>"]}]}
```
- Sources: user groups via `update_user` `auto_groups` (resend `role`, `is_blocked`); peers inherit them while account setting `groups_propagation_enabled` is on (default). Destinations: server groups via `create_setup_key` `auto_groups` or `update_group` `peers` (resend `name`, `resources`). Never mix laptops and servers in one group.
- `bidirectional: false` unless both sides initiate; replies pass statefully. Resource policies are always one-way and skip the routing peer itself; services on it need a peer policy.
- DNS resolvers behind NetBird need two policies, `udp` and `tcp`, port "53"; missing DNS is the most common breakage.

## Replace the Default policy
New accounts have `Default`: `All` to `All`, `all`, bidirectional. While enabled, narrower peer policies restrict nothing. Network resources are not in `All` and always need their own policy.
1. Create the specific policies, DNS included.
2. Ask the user to confirm: disabling Default cuts every flow no other policy allows, at once. Then `get_policy` Default, `update_policy` with `enabled: false`, all else unchanged.
3. `list_accessible_peers` on typical peers; if an expected peer is missing, re-enable Default and fix.
4. `delete_policy` only after the user confirms.

## Posture checks
Cloud: Business plan. `create_posture_check`: `name` (unique), `description` (required, may be ""), `checks` (always send). Fill only needed keys; every check must pass. Checks apply to source peers only and do not stop a compromised device.
- `nb_version_check`: `{"min_version":"0.61.0"}`
- `os_version_check`: `android`/`darwin`/`ios` `{"min_version"}`, `linux`/`windows` `{"min_kernel_version"}` (Windows 11 23H2 = "10.0.22631"). A peer on one of these five OSes that you omit fails; "0" admits any version. Client 0.26.0+.
- `geo_location_check`: `{"action":"allow|deny","locations":[{"country_code":"DE","city_name":"Berlin"}]}`. Uppercase ISO alpha-2 from `list_countries`; `city_name` must match a `list_country_cities` entry exactly; omit it for a whole country. Unknown location fails both actions. Self-hosted needs the geo database.
- `peer_network_range_check`: `{"action":"allow|deny","ranges":["192.168.1.0/24","203.0.113.10/32"]}`. Matches the public connection IP and NIC subnets (range not narrower than the subnet). Android <0.77.1 and iOS <0.69.0 report no NICs: LAN `allow` fails, LAN `deny` never triggers. `deny` + office LAN keeps on-site devices off a route.
- `process_check`: `{"processes":[{"linux_path":"...","mac_path":"...","windows_path":"..."}]}`. Exact paths, all running; only Linux, macOS, Windows can pass.
- `certificate_check`: `{"ca_certificates":["<PEM>"]}`. Re-proved every 4 hours. Client and management 0.81.0+; iOS/Android fail.
Attach with `source_posture_checks` on `create_policy`/`update_policy`; a failing peer loses only that policy. `update_posture_check` replaces all of `checks`. Detach before `delete_posture_check`.

## SSH
Needs client 0.61.0+ on both ends and the target running `--allow-server-ssh` (not settable here; check `get_peer` `local_flags.server_ssh_allowed`).
1. Keep `ssh_enabled` false on the targets (`get_peer`). A `netbird-ssh` policy turns the SSH server on by itself. `ssh_enabled: true` is the legacy switch: with any `all` or `tcp` port 22 policy to the peer, the Default policy included, it lets every user in the account log in as any local user, whatever `authorized_groups` says. If it is true, set it false with `update_peer`, resending `name`, `login_expiration_enabled`, `inactivity_expiration_enabled`.
2. `create_policy`: `protocol: "netbird-ssh"`, `ports: ["22"]`, `bidirectional: false`, sources = user groups, destinations = servers. `authorized_groups` maps user group IDs (users' `auto_groups`) to local users: `{"<admins id>":["ubuntu"],"<devs id>":["deploy"]}`. If set, include every source group; `[]` allows any local user; omitted is Full Access (any active non-service user, any local user).
`root` also needs `--enable-ssh-root`; `--disable-ssh-auth` disables user mapping. A `tcp` port "22" policy is only network access to an SSH daemon on the host, with no NetBird user mapping.

## Temporary access
No tool creates expiring access: use a dedicated policy with the end date in `description`, then disable it. Setup key `expires_in` only stops enrollment; enrolled peers stay until `delete_peer`. `ephemeral: true` keys drop peers 10 minutes after they go offline. Leave `Temporary access policy for peer ...` policies alone (browser client).

## Verify
- `get_policy` (resolved groups, posture IDs); `list_accessible_peers` (the peer's map, both directions, after posture checks).
- `get_peer`: `groups` and the values posture checks read (`version`, `os`, `kernel_version`, `country_code`, `connection_ip`, `network_addresses`).
- `list_audit_events`: who changed which policy, group or posture check, and when.
Changes reach peers immediately; posture is re-evaluated at login and on metadata change.
