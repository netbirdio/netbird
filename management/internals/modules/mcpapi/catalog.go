package mcpapi

import (
	"net/http"
	"reflect"

	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// param is a query parameter a tool accepts.
type param struct {
	name        string
	description string
}

// operation maps one MCP tool onto one REST operation.
type operation struct {
	name        string
	title       string
	description string
	method      string
	// path is the request path with the tool's path arguments in braces,
	// e.g. "/api/peers/{peer_id}". Every brace name must have an entry in
	// pathParamDescriptions.
	path  string
	query []param
	// body is the generated request type sent as the JSON body, nil when the
	// operation takes none. Its fields are merged into the tool's input schema.
	body reflect.Type
	// readOnly marks operations that never change state.
	readOnly bool
	// destructive marks operations that can remove or overwrite state: deletes and the
	// full-object replacements update tools send.
	destructive bool
}

// callerBound are path arguments dispatch fills from the caller instead of taking them from
// the client, so a tool only ever acts on the account the request is authenticated for, the
// one a tenant URL pins. The REST handler would accept any account the user may manage.
var callerBound = map[string]func(auth.UserAuth) string{
	"account_id": func(userAuth auth.UserAuth) string { return userAuth.AccountId },
}

// pathParamDescriptions documents every path argument the client supplies.
var pathParamDescriptions = map[string]string{
	"user_id":          "ID of the user, as returned by list_users.",
	"peer_id":          "ID of the peer, as returned by list_peers.",
	"key_id":           "ID of the setup key, as returned by list_setup_keys.",
	"group_id":         "ID of the group, as returned by list_groups.",
	"policy_id":        "ID of the policy, as returned by list_policies.",
	"posture_check_id": "ID of the posture check, as returned by list_posture_checks.",
	"route_id":         "ID of the route, as returned by list_routes.",
	"network_id":       "ID of the network, as returned by list_networks.",
	"resource_id":      "ID of the network resource, as returned by list_network_resources.",
	"router_id":        "ID of the network router, as returned by list_network_routers.",
	"nsgroup_id":       "ID of the nameserver group, as returned by list_nameserver_groups.",
	"zone_id":          "ID of the DNS zone, as returned by list_dns_zones.",
	"record_id":        "ID of the DNS record, as returned by list_dns_records.",
	"country":          "Two-letter ISO 3166-1 alpha-2 country code, as returned by list_countries.",
}

const replaceNote = " The request replaces the stored object: fetch it first and send every field back, changed or not."

func bodyOf[T any]() reflect.Type {
	return reflect.TypeFor[T]()
}

func read(name, title, description, path string, query ...param) operation {
	return operation{name: name, title: title, description: description, method: http.MethodGet, path: path, query: query, readOnly: true}
}

func create(name, title, description, path string, body reflect.Type) operation {
	return operation{name: name, title: title, description: description, method: http.MethodPost, path: path, body: body}
}

func update(name, title, description, path string, body reflect.Type) operation {
	// Replacing the stored object can drop fields and revoke or reassign things, so update
	// tools are destructive in the MCP sense: not only additive.
	return operation{name: name, title: title, description: description + replaceNote, method: http.MethodPut, path: path, body: body, destructive: true}
}

func remove(name, title, description, path string) operation {
	return operation{name: name, title: title, description: description, method: http.MethodDelete, path: path, destructive: true}
}

// catalog lists every tool the server can expose, in the order they are
// advertised. Account deletion is left out on purpose: it is guarded by a
// middleware on the root router that in-process dispatch does not pass through.
var catalog = []operation{
	read("get_account", "Get account",
		"Retrieve the caller's account with its settings. Returns a JSON array holding exactly the caller's account. Use its whole settings object as the base for update_account. network_range and network_range_v6 show the effective ranges even when no custom range is set.",
		"/api/accounts"),
	update("update_account", "Update account",
		"Update the settings of the caller's account. Needs the owner or admin role. Arguments: settings (the full object from get_account, edited); leave onboarding out. Omitted fields reset to zero values: dns_domain returns to the default, a missing ipv6_enabled_groups removes IPv6 from all peers, lazy_connection_enabled, groups_propagation_enabled and routing_peer_dns_resolution_enabled turn false, and auto_update_version is cleared. Always send settings.extra with its five fields. peer_login_expiration is in seconds, 3600 to 15552000, even when disabled. network_range is IPv4, /28 or larger; changing it re-addresses every peer. ipv6_enabled_groups must be existing group IDs. auto_update_version is disabled, latest or a version such as 0.61.0; other values fail with HTTP 500. peer_expose_enabled true needs a group in peer_expose_groups. agent_network_only true needs dashboard_features.agent_network true. Turning extra.peer_approval_enabled off approves all pending peers.",
		"/api/accounts/{account_id}", bodyOf[api.PutApiAccountsAccountIdJSONRequestBody]()),

	read("list_users", "List users",
		"List the users of the account, including their role, status, groups and whether they are service users.",
		"/api/users",
		param{"service_user", "true lists only service users, false lists only regular users; omit for both."}),
	read("get_current_user", "Get current user",
		"Retrieve the user that owns the token making this call.",
		"/api/users/current"),
	create("create_user", "Create user",
		"Invite a regular user or create a service user. Needs the owner or admin role. Required: role, auto_groups (existing group IDs added to the user's peers; may be empty; never the All group) and is_service_user. Roles: admin, network_admin, auditor, billing_admin, user, agent_network_admin or usage_viewer; owner is rejected. For an invite (is_service_user false), email and name are required. On NetBird Cloud the user receives an invitation email, and an email that already has a NetBird account fails with 409. With the self-hosted embedded IdP, the response holds a generated password once. For a service user (is_service_user true), set name; email is ignored. Service users act through access tokens, which no tool here creates.",
		"/api/users", bodyOf[api.PostApiUsersJSONRequestBody]()),
	update("update_user", "Update user",
		"Change a user's role, auto-assigned groups or blocked state. Needs the owner or admin role. Required: user_id, role, auto_groups and is_blocked; copy current values from list_users. Roles: owner, admin, network_admin, auditor, billing_admin, user, agent_network_admin, usage_viewer. Admins and the owner cannot change their own role or block themselves. Only the owner can assign owner, which transfers ownership and makes the previous owner an admin. The owner cannot be blocked, and service users cannot be owner. auto_groups must exist and cannot include the All group; with groups_propagation_enabled the change also applies to the user's peers. Blocking a user expires their peers, which must log in again. This tool cannot approve a user with pending_approval: is_blocked false leaves them pending.",
		"/api/users/{user_id}", bodyOf[api.PutApiUsersUserIdJSONRequestBody]()),
	remove("delete_user", "Delete user",
		"Remove a user from the account. The user's peers are removed as well. Use this to reject a user who is pending approval. The caller cannot delete itself, the owner cannot be deleted, non-deletable service users cannot be deleted, and a user provisioned by an IdP sync integration can only be deleted by a service user.",
		"/api/users/{user_id}"),
	create("approve_user", "Approve user",
		"Approve a user who is pending approval (pending_approval true in list_users, with the account setting extra.user_approval_required on). update_user cannot do this. Needs the owner or admin role.",
		"/api/users/{user_id}/approve", nil),
	remove("reject_user", "Reject user",
		"Reject a user who is pending approval by removing them from the account. The audit log records it as a rejection.",
		"/api/users/{user_id}/reject"),

	read("list_peers", "List peers",
		"List the peers (devices) in the account with their IPs, connection status, OS, groups and owner. Filters are optional and combine.",
		"/api/peers",
		param{"name", "Filter peers by name."},
		param{"ip", "Filter peers by overlay IP address."},
		param{"mac", "Filter peers by the MAC address of a network interface."}),
	read("get_peer", "Get peer",
		"Retrieve one peer with its full details: groups, login expiration, ssh_enabled and local_flags (server_ssh_allowed shows whether the device runs the SSH server). It also returns the values posture checks evaluate: version, os, kernel_version, country_code, city_name, connection_ip and network_addresses.",
		"/api/peers/{peer_id}"),
	update("update_peer", "Update peer",
		"Rename a peer, approve it, or change its SSH flag, login expiration, inactivity expiration or overlay IP. Required: peer_id, name, ssh_enabled, login_expiration_enabled, inactivity_expiration_enabled; copy current values from get_peer. approval_required false approves a pending peer and fails when an EDR integration covers it; true does not revoke approval. The expiration flags can only change on peers added by SSO login (non-empty user_id). A netbird-ssh policy enables a peer's SSH server without ssh_enabled, so keep ssh_enabled false. ssh_enabled true is the legacy switch: with any all or tcp port 22 policy to the peer, the Default policy included, every user in the account can log in as any local user, whatever a netbird-ssh policy's authorized_groups say. Either way the device must run netbird up --allow-server-ssh, which no tool can set. ip and ipv6 are optional: omit them unless reassigning; the address must be inside the account range, unused and not reserved, and it is applied even if the rest of the update fails. Group membership is changed with update_group.",
		"/api/peers/{peer_id}", bodyOf[api.PutApiPeersPeerIdJSONRequestBody]()),
	remove("delete_peer", "Delete peer",
		"Remove a peer from the account. The device loses access until it enrolls again.",
		"/api/peers/{peer_id}"),
	read("list_accessible_peers", "List accessible peers",
		"List the peers in a given peer's network map under the current policies: peers it may connect to and peers allowed to connect to it, after posture checks, plus the routing peers of network resources it may reach. Use it to verify a new policy or the effect of disabling the Default policy; while Default is enabled every peer is listed. Network resources themselves are not listed.",
		"/api/peers/{peer_id}/accessible-peers"),

	read("list_setup_keys", "List setup keys",
		"List the setup keys used to enroll new peers, with their type, usage, expiry and auto-assigned groups. Key secrets are not returned.",
		"/api/setup-keys"),
	read("get_setup_key", "Get setup key",
		"Retrieve one setup key. The secret is only returned by create_setup_key.",
		"/api/setup-keys/{key_id}"),
	create("create_setup_key", "Create setup key",
		"Create a setup key for enrolling peers without SSO login (servers, routing peers, automation). Required: name, type (one-off or reusable), expires_in (seconds, 86400 to 31536000; 0 means never expires), auto_groups (existing group IDs, may be empty, never the All group) and usage_limit (0 means unlimited; one-off keys are always limited to 1 and reject values above 1). Optional: ephemeral (peers are deleted after 10 minutes offline) and allow_extra_dns_labels (peers may register extra DNS labels with --extra-dns-labels). auto_groups apply only to peers enrolled after they are set, and access still needs a policy on those groups. The response holds the plain key secret once; it cannot be read again. Enroll with netbird up --setup-key <key>.",
		"/api/setup-keys", bodyOf[api.PostApiSetupKeysJSONRequestBody]()),
	update("update_setup_key", "Update setup key",
		"Revoke a setup key or change its auto-assigned groups. Required: key_id, revoked and auto_groups (existing group IDs, never the All group). No other property can change. Revoking is permanent: sending revoked false for a revoked key fails. Revoking does not disconnect peers that already enrolled, and auto_groups changes apply only to peers enrolled afterwards.",
		"/api/setup-keys/{key_id}", bodyOf[api.PutApiSetupKeysKeyIdJSONRequestBody]()),
	remove("delete_setup_key", "Delete setup key",
		"Delete a setup key. Peers already enrolled with it keep working.",
		"/api/setup-keys/{key_id}"),

	read("list_groups", "List groups",
		"List the groups with their peer and resource counts. Groups are the building block of policies, routes and DNS distribution.",
		"/api/groups",
		param{"name", "Filter groups by exact name."}),
	read("get_group", "Get group",
		"Retrieve one group with its peers and resources.",
		"/api/groups/{group_id}"),
	create("create_group", "Create group",
		"Create a group, optionally with an initial list of peer IDs and resources.",
		"/api/groups", bodyOf[api.PostApiGroupsJSONRequestBody]()),
	update("update_group", "Update group",
		"Rename a group or set its peers and resources. Required: group_id and name. peers and resources replace the stored lists: leaving either out empties it, which drops those peers or resources from every policy, route and network router using the group. Call get_group first and send peers as peer ID strings (get_group returns objects) and resources as {id, type} (type peer, host, subnet or domain). The All group cannot be updated. Group membership grants no access without a policy.",
		"/api/groups/{group_id}", bodyOf[api.PutApiGroupsGroupIdJSONRequestBody]()),
	remove("delete_group", "Delete group",
		"Delete a group. Fails for the All group, for a group that holds network resources, and while the group is referenced by a policy, route, nameserver group, setup key, user auto_groups, network router, reverse proxy service, agent network policy or budget rule, the DNS management exclusions, the traffic event logging groups or an EDR integration. A group provisioned by an IdP sync integration can only be deleted by a service user with the admin role.",
		"/api/groups/{group_id}"),

	read("list_policies", "List policies",
		"List the access control policies. Each policy holds one rule: sources and destinations as group objects {id, name, peers_count}, or sourceResource/destinationResource {id, type}; protocol; ports or port_ranges; bidirectional; action; authorized_groups for netbird-ssh rules; plus source_posture_checks (posture check IDs). New accounts have a policy named Default that allows the All group to All on every protocol in both directions; while it is enabled, narrower peer policies restrict nothing. Network resources are not members of All, so they are reachable only through policies that name them.",
		"/api/policies"),
	read("get_policy", "Get policy",
		"Retrieve one access control policy. Call it before update_policy: send back the rule id and description, convert sources and destinations from group objects to their id strings, omit a sources or destinations key that is null (the rule uses a resource instead), and keep ports or port_ranges, authorized_groups and source_posture_checks.",
		"/api/policies/{policy_id}"),
	create("create_policy", "Create policy",
		"Create an access control policy. Send exactly one rule in rules and create one policy per flow: rule IDs default to the policy ID, so a second rule collides. Rule fields: name, enabled, action (accept; drop exists in the spec but the docs describe allow-only policies), bidirectional (false for one-way; traffic to network resources is always one-way), protocol (all, tcp, udp, icmp or netbird-ssh), and ports (strings \"1\" to \"65535\") or port_ranges [{start, end}], never both; to mix, send single ports as ranges with start equal to end. No ports with all or icmp; tcp, udp or netbird-ssh without ports opens every port. Each side takes group IDs (sources, destinations) or one resource {id, type} (sourceResource, destinationResource; type peer, or host, subnet or domain for a network resource as destination), never both; omit the unused key instead of sending []. For netbird-ssh set ports [\"22\"] and optionally authorized_groups, a map of user group ID to allowed local users that must contain every source group; an empty list allows any local user. source_posture_checks takes posture check IDs. Unknown group or posture check IDs are dropped without an error, so pass IDs, not names, and compare the response with the request. A route with access_control_groups needs a policy whose destinations include that group.",
		"/api/policies", bodyOf[api.PostApiPoliciesJSONRequestBody]()),
	update("update_policy", "Update policy",
		"Change a policy's name, description, enabled state, rule or source_posture_checks. Fetch it with get_policy first and keep the rule's id. Send sources and destinations as group ID strings, and omit sources when a rule uses sourceResource and destinations when it uses destinationResource: an empty list counts as set and is rejected. Resend description and source_posture_checks: an omitted description becomes empty and an omitted source_posture_checks detaches every posture check. Set enabled false to suspend a policy reversibly; ask the user before disabling the Default policy, which cuts every flow no other policy allows at once. Same rule constraints as create_policy.",
		"/api/policies/{policy_id}", bodyOf[api.PutApiPoliciesPolicyIdJSONRequestBody]()),
	remove("delete_policy", "Delete policy",
		"Delete an access control policy. Traffic it allowed is blocked once peers receive the update. Deleting the Default policy before narrower policies exist stops all peer traffic: disable it with update_policy first, check list_accessible_peers, and delete only after the user confirms.",
		"/api/policies/{policy_id}"),

	read("list_posture_checks", "List posture checks",
		"List the posture checks with their definitions: nb_version_check, os_version_check, geo_location_check, peer_network_range_check, process_check and certificate_check. A posture check has no effect until its ID is in a policy's source_posture_checks.",
		"/api/posture-checks"),
	read("get_posture_check", "Get posture check",
		"Retrieve one posture check with its check definitions. Call it before update_posture_check, which replaces the whole checks object.",
		"/api/posture-checks/{posture_check_id}"),
	create("create_posture_check", "Create posture check",
		"Create a posture check. name must be unique, description is required (may be empty) and checks must be sent with at least one key: nb_version_check {min_version}; os_version_check with android, darwin, ios {min_version} and linux, windows {min_kernel_version}, where a peer on one of these five OSes left out fails; geo_location_check {action allow or deny, locations [{country_code (ISO 3166-1 alpha-2, uppercase), city_name (optional, English)}]}; peer_network_range_check {action allow or deny, ranges [CIDR]}, matched against the peer's local interface subnets and its public connection IP; process_check {processes [{linux_path, mac_path, windows_path}]}, all of which must be running, and only Linux, macOS and Windows peers can pass; certificate_check {ca_certificates [PEM]}, which iOS and Android always fail. Every configured check must pass. Checks are evaluated on the source peers of the policies that list the posture check ID in source_posture_checks.",
		"/api/posture-checks", bodyOf[api.PostApiPostureChecksJSONRequestBody]()),
	update("update_posture_check", "Update posture check",
		"Change a posture check's name, description or check definitions. Send the full checks object: a check type left out is removed. Policies that reference the check are recomputed and pushed to peers.",
		"/api/posture-checks/{posture_check_id}", bodyOf[api.PutApiPostureChecksPostureCheckIdJSONRequestBody]()),
	remove("delete_posture_check", "Delete posture check",
		"Delete a posture check. Fails while a policy references it: remove its ID from that policy's source_posture_checks with update_policy first.",
		"/api/posture-checks/{posture_check_id}"),
	read("list_countries", "List countries",
		"List the ISO 3166-1 alpha-2 country codes known to the geolocation database, for country_code in a posture check's geo_location_check.",
		"/api/locations/countries"),
	read("list_country_cities", "List cities of a country",
		"List the English city names of a country, for city_name in a posture check's geo_location_check, which must match one of them exactly.",
		"/api/locations/countries/{country}/cities"),

	read("list_routes", "List routes",
		"List the network routes (legacy routing, including exit nodes with network 0.0.0.0/0) with network or domains, network_type (IPv4, IPv6 or Domain), peer or peer_groups, distribution groups (groups), access_control_groups, metric, masquerade, enabled and skip_auto_apply. Routes sharing network_id and network are one highly available route. peer is an empty string on group-based routes, and domain routes carry the placeholder network 192.0.2.0/32. The ::/0 counterpart of an exit node is generated per peer and is not listed.",
		"/api/routes"),
	read("get_route", "Get route",
		"Retrieve one network route.",
		"/api/routes/{route_id}"),
	create("create_route", "Create route",
		"Create a network route. Routes are deprecated except for exit nodes: use the Networks tools for hosts, subnets and domains. Required: network_id (the route's own 1-40 character label that clients see, not an ID from list_networks; routes sharing network_id and network form one highly available route), description, enabled, metric (1-9999, lower wins), masquerade, keep_route (only affects domain routes) and groups (non-empty distribution group IDs whose peers receive the route, not routing peers). Set exactly one of network (CIDR; 0.0.0.0/0 makes an exit node) or domains (up to 32), and exactly one of peer (routing peer ID) or peer_groups (routing peer group IDs, sharing one metric). masquerade true NATs to the routing peer's address; only Linux routing peers can turn it off. skip_auto_apply on an exit node: false applies it on clients automatically, true only offers it. A peer receives the route only if a policy connects it to the routing peer. Without access_control_groups the whole range is open; with them, traffic needs a policy whose destinations include that group, and LAN-sourced traffic needs masquerade true. Do not reuse a routing peer for the same network in a second route, and do not use a routing peer that also serves networks.",
		"/api/routes", bodyOf[api.PostApiRoutesJSONRequestBody]()),
	update("update_route", "Update route",
		"Change a network route; fields and rules as in create_route. route_id is the path ID and network_id the route label. Build the body from get_route: drop id and network_type, drop peer when it is an empty string and peer_groups is set, and send only one of network or domains (get_route returns domains null on network routes and the placeholder network 192.0.2.0/32 on domain routes). Sending both of either pair fails with HTTP 422. Resend skip_auto_apply and access_control_groups: omitted, they reset to false (an exit node auto-applies) and empty (all routed traffic allowed).",
		"/api/routes/{route_id}", bodyOf[api.PutApiRoutesRouteIdJSONRequestBody]()),
	remove("delete_route", "Delete route",
		"Delete a network route.",
		"/api/routes/{route_id}"),

	read("list_networks", "List networks",
		"List the networks. Each network is a container for the resources (hosts, subnets, domains) and routing peers of one environment, and lists the IDs of its routers, its resources and the policies associated with them, plus routing_peers_count.",
		"/api/networks"),
	read("get_network", "Get network",
		"Retrieve one network with its router IDs, resource IDs, routing_peers_count and policies (IDs of enabled policies that target its resources). Empty policies means no resource in the network is routed. routing_peers_count counts configured routing peers, offline ones and disabled routers included; check connected in list_peers for liveness. Use list_network_resources and list_network_routers for details.",
		"/api/networks/{network_id}"),
	create("create_network", "Create network",
		"Create a network: a container that maps one environment (office LAN, cloud VPC, data center) onto the overlay. name is required, description is optional. Then add resources with create_network_resource, routing peers with create_network_router, and a create_policy rule whose destinations are the resource groups; nothing in a network is reachable until a policy allows it. Prefer networks over create_route except for exit nodes and site-to-site that must keep source IPs.",
		"/api/networks", bodyOf[api.PostApiNetworksJSONRequestBody]()),
	update("update_network", "Update network",
		"Change a network's name or description. Its resources and routers are not affected.",
		"/api/networks/{network_id}", bodyOf[api.PutApiNetworksNetworkIdJSONRequestBody]()),
	remove("delete_network", "Delete network",
		"Delete a network together with all its resources and routers; the resources are also removed from their groups. Policies and groups are kept.",
		"/api/networks/{network_id}"),
	read("list_network_resources", "List network resources",
		"List the resources of a network with address, type (host, subnet or domain), enabled and groups. groups are returned as objects with id and name.",
		"/api/networks/{network_id}/resources"),
	read("get_network_resource", "Get network resource",
		"Retrieve one network resource. groups are returned as objects; send their id values to update_network_resource.",
		"/api/networks/{network_id}/resources/{resource_id}"),
	create("create_network_resource", "Create network resource",
		"Add a resource to a network. Arguments: network_id, name (unique across the account; clients show it in netbird networks ls), address, groups (existing group IDs), enabled, optional description. address is a host (10.0.0.5 or 10.0.0.5/32), a subnet by its network address (10.0.0.0/24) or a domain (app.corp.local, *.corp.local); the server derives type host, subnet or domain. A plain domain matches only that name; a wildcard matches subdomains only, not the base name. Send enabled: true; omitted means disabled. groups are resource groups that policies use as destinations; keep them to resources, since a peer in such a group also becomes a destination. Resources are not in the All group: nothing reaches one until an enabled policy names its group in destinations (or the resource in destinationResource) and the network has an enabled router. With routing_peer_dns_resolution_enabled on (the default) the routing peer resolves domain resources, so it must resolve the name. Keep domain and subnet resources in separate networks: a domain resolving into a subnet resource's CIDR falls under both policies.",
		"/api/networks/{network_id}/resources", bodyOf[api.PostApiNetworksNetworkIdResourcesJSONRequestBody]()),
	update("update_network_resource", "Update network resource",
		"Change a network resource: name (still unique in the account), address, description, enabled and groups. Send groups as group IDs (get_network_resource returns objects) and omit id and type; an omitted enabled means disabled. Removing a group detaches the resource from the policies that target that group.",
		"/api/networks/{network_id}/resources/{resource_id}", bodyOf[api.PutApiNetworksNetworkIdResourcesResourceIdJSONRequestBody]()),
	remove("delete_network_resource", "Delete network resource",
		"Remove a resource from its network and from its groups. Fails while a reverse proxy service targets the resource.",
		"/api/networks/{network_id}/resources/{resource_id}"),
	read("list_network_routers", "List network routers",
		"List the routers of a network with peer (a peer ID), peer_groups (group IDs), metric, masquerade and enabled. Both peer and peer_groups are returned; the one not in use is empty.",
		"/api/networks/{network_id}/routers"),
	read("get_network_router", "Get network router",
		"Retrieve one network router with peer or peer_groups, metric, masquerade and enabled.",
		"/api/networks/{network_id}/routers/{router_id}"),
	create("create_network_router", "Create network router",
		"Add a routing peer or peer group to a network. Arguments: network_id, exactly one of peer (a peer ID) or peer_groups (group IDs), metric (1-9999, lower wins), masquerade, enabled. The server does not check that the peer or groups exist, so take IDs from list_peers or list_groups. The router is always created enabled. Send masquerade: true unless source IPs must be kept; omitted means false. masquerade true SNATs forwarded traffic to the routing peer's LAN IP; false works only on Linux routing peers and needs a return route for the account network range (get_account settings.network_range) via the active routing peer's LAN IP on the destination network. Site-to-site through networks needs masquerade true on both sides. For high availability add one router per peer: different metrics give primary and failover, equal metrics let each client pick by connection type, then latency; peer_groups members share one metric. This is not load balancing. A router serves a resource only after an enabled policy targets it.",
		"/api/networks/{network_id}/routers", bodyOf[api.PostApiNetworksNetworkIdRoutersJSONRequestBody]()),
	update("update_network_router", "Update network router",
		"Change a network router: network_id, router_id, exactly one of peer or peer_groups (send the one in use; get_network_router returns the other empty), metric (1-9999, lower wins), masquerade, enabled. Omit id. masquerade and enabled are plain booleans: omitted means false, which disables masquerade or the router. masquerade false works only on Linux routing peers, needs a return route for the account network range on the destination network, and breaks site-to-site through networks.",
		"/api/networks/{network_id}/routers/{router_id}", bodyOf[api.PutApiNetworksNetworkIdRoutersRouterIdJSONRequestBody]()),
	remove("delete_network_router", "Delete network router",
		"Remove a router from a network.",
		"/api/networks/{network_id}/routers/{router_id}"),
	read("list_all_network_routers", "List all network routers",
		"List the routers of every network in the account with peer or peer_groups, metric, masquerade and enabled. A router carries no network ID: match its id against the routers of list_networks to find its network, for example to see which networks a peer routes for.",
		"/api/networks/routers"),

	read("list_nameserver_groups", "List nameserver groups",
		"List the nameserver groups with their nameservers, primary flag, match domains, search_domains_enabled, enabled state and distribution groups.",
		"/api/dns/nameservers"),
	read("get_nameserver_group", "Get nameserver group",
		"Retrieve one nameserver group.",
		"/api/dns/nameservers/{nsgroup_id}"),
	create("create_nameserver_group", "Create nameserver group",
		"Create a nameserver group used by the peers in its distribution groups. All fields are required: name (1-40 chars, unique), description (may be empty), nameservers (1-3 objects {ip, ns_type: udp, port}), enabled, groups (non-empty group IDs), primary, domains, search_domains_enabled. Primary group, resolving all domains: primary true, domains [], search_domains_enabled false. Match-domain group: primary false and at least one domain; wildcards are rejected, a domain covers its subdomains, the most specific match wins. Give each peer exactly one primary. Match domains are honored on macOS, Windows 10+ and Linux with systemd-resolved. Include a routing peer's group when it must resolve domain resources. A DNS server reachable only through a routing peer also needs a network resource and a UDP 53 policy.",
		"/api/dns/nameservers", bodyOf[api.PostApiDnsNameserversJSONRequestBody]()),
	update("update_nameserver_group", "Update nameserver group",
		"Change a nameserver group. Same field rules as create_nameserver_group. To add a primary next to a match-domain group, create a second group with the same servers instead of emptying domains, which also removes the search domains.",
		"/api/dns/nameservers/{nsgroup_id}", bodyOf[api.PutApiDnsNameserversNsgroupIdJSONRequestBody]()),
	remove("delete_nameserver_group", "Delete nameserver group",
		"Delete a nameserver group. Create a replacement primary group before deleting the current one, or peers fall back to their original DNS settings.",
		"/api/dns/nameservers/{nsgroup_id}"),
	read("get_dns_settings", "Get DNS settings",
		"Retrieve the account DNS settings: disabled_management_groups, the groups whose peers NetBird does not configure DNS on.",
		"/api/dns/settings"),
	update("update_dns_settings", "Update DNS settings",
		"Set disabled_management_groups, the group IDs whose peers run in unmanaged DNS mode: NetBird leaves their system DNS untouched and they ignore nameserver groups and DNS zones. The list replaces the stored one. Use it for a Domain Controller that acts as a routing peer.",
		"/api/dns/settings", bodyOf[api.PutApiDnsSettingsJSONRequestBody]()),
	read("list_dns_zones", "List DNS zones",
		"List the custom DNS zones with domain, enabled, enable_search_domain, distribution groups and records.",
		"/api/dns/zones"),
	read("get_dns_zone", "Get DNS zone",
		"Retrieve one DNS zone.",
		"/api/dns/zones/{zone_id}"),
	create("create_dns_zone", "Create DNS zone",
		"Create a custom DNS zone that NetBird serves to the peers in distribution_groups. Arguments: name (1-255 chars), domain (FQDN, no wildcard, unique in the account, cannot be changed later, must differ from the peer DNS domain such as netbird.cloud or the account dns_domain), distribution_groups (at least one group ID), enable_search_domain, optional enabled (default true). A zone is distributed only once it has records and takes precedence over a nameserver group with the same match domain. Peers in DNS-unmanaged groups ignore it. When its names are also domain resources of a network, include the routing peer's group.",
		"/api/dns/zones", bodyOf[api.PostApiDnsZonesJSONRequestBody]()),
	update("update_dns_zone", "Update DNS zone",
		"Change a zone's name, enabled, enable_search_domain or distribution_groups. domain cannot change: send the stored value, or delete and recreate the zone. An omitted enabled means true, so send the stored value to keep a zone disabled.",
		"/api/dns/zones/{zone_id}", bodyOf[api.PutApiDnsZonesZoneIdJSONRequestBody]()),
	remove("delete_dns_zone", "Delete DNS zone",
		"Delete a DNS zone together with its records.",
		"/api/dns/zones/{zone_id}"),
	read("list_dns_records", "List DNS records",
		"List the records of a DNS zone with name (full FQDN), type, content and ttl.",
		"/api/dns/zones/{zone_id}/records"),
	read("get_dns_record", "Get DNS record",
		"Retrieve one DNS record.",
		"/api/dns/zones/{zone_id}/records/{record_id}"),
	create("create_dns_record", "Create DNS record",
		"Add a record to a DNS zone. name is the full FQDN and must equal the zone domain or end with .<zone domain> (for zone netbird.internal send db.netbird.internal, not db). type is A (content an IPv4 address), AAAA (an IPv6 address) or CNAME (a domain without wildcard). ttl is in seconds, 0 or more; send it explicitly (300 is the dashboard default). A CNAME cannot share its name with any other record, A, AAAA or CNAME, and identical records are rejected.",
		"/api/dns/zones/{zone_id}/records", bodyOf[api.PostApiDnsZonesZoneIdRecordsJSONRequestBody]()),
	update("update_dns_record", "Update DNS record",
		"Change a DNS record's name, type, content or ttl. The create_dns_record rules apply: name is the full FQDN inside the zone.",
		"/api/dns/zones/{zone_id}/records/{record_id}", bodyOf[api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody]()),
	remove("delete_dns_record", "Delete DNS record",
		"Delete a DNS record.",
		"/api/dns/zones/{zone_id}/records/{record_id}"),

	read("list_audit_events", "List audit events",
		"List the audit events of the account: who changed what and when, newest first.",
		"/api/events/audit"),
}
