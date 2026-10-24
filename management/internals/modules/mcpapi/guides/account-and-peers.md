# Account settings, peers, setup keys, users and groups

Changing settings, peers, setup keys or users needs the `owner` or `admin` role; `network_admin` can still edit groups.

## update_account replaces every setting
1. `get_account` returns a one-item array. Take its whole `settings` object.
2. Call `update_account` with `{"settings":{...every field from get_account, edited...}}` and no `account_id`: it always acts on the caller's account. Leave out `onboarding`.
3. Omitted fields reset to zero values: `dns_domain` to the default, a missing `ipv6_enabled_groups` removes IPv6 from all peers, `lazy_connection_enabled`, `groups_propagation_enabled` and `routing_peer_dns_resolution_enabled` turn false, `auto_update_version` is cleared. Always send `extra` with all five fields.
4. `peer_login_expiration` must be 3600 to 15552000 seconds, even when expiration is off.

## Settings (inside `settings`)
- `peer_login_expiration_enabled`, `peer_login_expiration` (seconds, default 86400): SSO peers (non-empty `user_id`) must log in again. Enabling or shortening it can disconnect them at once.
- `peer_inactivity_expiration_enabled`, `peer_inactivity_expiration` (seconds, default 600): SSO peers disconnected from management longer than this must log in again.
- `regular_users_view_blocked` (default true): `user`, `billing_admin` and `usage_viewer` users see no peers, not even their own.
- `groups_propagation_enabled` (default true): a user's `auto_groups` apply to all their peers. Enabling adds missing memberships once; disabling keeps them.
- JWT sync (self-hosted): `jwt_groups_enabled`, `jwt_groups_claim_name`, `jwt_allow_groups` (group names from the claim). A non-empty allow list locks out users lacking them, you included.
- `network_range`: IPv4 CIDR, /28 or larger, not loopback, multicast or link-local, room for peers x1.5 (min 10). Changing it re-addresses every peer.
- `network_range_v6` (/48 to /120), `ipv6_enabled_groups` (existing group IDs; clients v0.71.0+). `[]` turns IPv6 off.
- `dns_domain`: no wildcards, not a custom DNS zone's domain; use a subdomain with no public records. `""` = default.
- `lazy_connection_enabled` (clients v0.50.1+): a link stays closed only when both ends are lazy. `NB_LAZY_CONN` on a client overrides it.
- `routing_peer_dns_resolution_enabled` (clients v0.35+, after client restart).
- `auto_update_version`: `"disabled"`, `"latest"` or `"0.61.0"` (no `v`); an invalid value returns HTTP 500. `auto_update_always: true` installs silently and restarts the client (v0.67.0+). Windows and macOS only, clients v0.61.0+, never downgrades.
- `peer_expose_enabled: true` needs a group in `peer_expose_groups` (clients v0.66.0+).
- `peer_hostname_collision_rejected` (duplicate hostnames fail, no suffix), `metrics_push_enabled` (v0.74.0+), `local_mfa_enabled` (embedded IdP), `agent_network_only` (needs `dashboard_features.agent_network: true`).
- `extra.peer_approval_enabled` (Cloud Business or self-hosted Enterprise): new peers wait for approval. Turning it off approves all pending peers; turning it on fails while an EDR integration is active.
- `extra.user_approval_required`: users joining by domain matching wait for approval.
- `extra.network_traffic_logs_enabled`, `network_traffic_logs_groups` (`[]` = all peers), `network_traffic_packet_counter_enabled`: Business plan, or Enterprise with traffic flow.

## Peers: update_peer
Call `get_peer`, then send `peer_id`, `name`, `ssh_enabled`, `login_expiration_enabled`, `inactivity_expiration_enabled` with current values plus your change. Omit `ip`, `ipv6` and `approval_required` unless changing them.
- Approve: `approval_required: false`. Fails when an EDR integration covers the peer. `true` does not revoke approval.
- Expiration flags change only on SSO peers; for setup-key peers send the current value.
- SSH: the peer must run `netbird up --allow-server-ssh` (v0.61.0+). A `netbird-ssh` policy to the peer enables SSH without `ssh_enabled`; keep `ssh_enabled` false. `ssh_enabled: true` is the legacy switch: with any `all` or `tcp` port 22 policy to the peer, Default included, every user in the account can log in as any local user.
- `ip` must be in `network_range`, unused and not reserved; it applies even if the rest fails.

## Setup keys
For servers, routing peers and automation. Prefer `one-off`.
```json
{"name":"k8s-nodes","type":"reusable","expires_in":2592000,"usage_limit":30,"auto_groups":["<group-id>"],"ephemeral":true}
```
- `type`: `one-off` (`usage_limit` 0 or 1) or `reusable` (0 = unlimited). `expires_in`: seconds, 86400 to 31536000; 0 = never.
- `auto_groups`: existing group IDs, never `All`; they apply only to peers enrolled later.
- `ephemeral`: peers deleted after 10 minutes offline.
- `create_setup_key` returns the `key` secret once. Enroll with `netbird up --setup-key <key>`.
- `update_setup_key` takes `key_id`, `revoked`, `auto_groups` (all required). Revoking is permanent. Revoked, expired or deleted keys do not disconnect enrolled peers.

## Users
Roles: `owner`, `admin`, `network_admin`, `auditor`, `billing_admin`, `user`, `agent_network_admin`, `usage_viewer`.
- Invite: `create_user` with `email`, `name`, `role` (not `owner`), `auto_groups`, `is_service_user: false`. Cloud emails an invite (409 if the email has an account); the embedded IdP returns a one-time `password`. Service user: `name`, `role`, `auto_groups`, `is_service_user: true`.
- `update_user` needs `user_id`, `role`, `auto_groups`, `is_blocked`. Admins and the owner cannot change their own role or block themselves. Only the owner can grant `owner`; the old owner becomes admin. The owner cannot be blocked. Blocking expires the user's peers.
- Users with `pending_approval: true` (`extra.user_approval_required`): `approve_user` approves, `reject_user` removes them. `update_user` with `is_blocked: false` does not approve.

## Groups
A group grants no access by itself; a policy must allow traffic. `update_group` replaces `peers` and `resources`: omitting either empties it, so resend what `get_group` returned. `All` cannot be changed. `delete_group` fails while anything references the group.

## Verify
`get_peer` (`login_expired`, `approval_required`, `ssh_enabled`, `ipv6`, `user_id`), `list_setup_keys` (`state`, `used_times`), `list_users` (`status`, `pending_approval`), `list_audit_events`.
