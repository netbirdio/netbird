package netbird

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# get_rule builds a netbird rule object from given parameters
get_rule(peer_id, direction, action, port) := rule if {
    peer := input.peers[_]
    peer.ID == peer_id
    rule := {
        "ID": peer.ID,
        "IP": peer.IP,
        "Direction": direction,
        "Action": action,
        "Port": port,
    }
}

# netbird_rules_from_group returns a list of netbird rules for a given group_id
rules_from_group(group_id, direction, action, port) := rules if {
	group := input.groups[_]
	group.ID == group_id
	rules := [get_rule(peer, direction, action, port) | peer := group.Peers[_]]
}

# is_peer_in_any_group checks that input peer present at least in one group
is_peer_in_any_group(groups) := count([group_id]) > 0 if {
	group_id := groups[_]
	group := input.groups[_]
	group.ID == group_id
	peer := group.Peers[_]
	peer == input.peer_id
}
