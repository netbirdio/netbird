package netbird

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# get_rule builds a netbird rule object from given parameters
get_rule(peer_id, peer_ip, direction, action, port) := rule if {
  rule := {
    "ID": peer_id,
    "IP": peer_ip,
    "Direction": direction,
    "Action": action,
    "Port": port,
  }
}

# peers_from_group returns a list of peer ids for a given group id
peers_from_group(group_id) := peers if {
  some group in input.groups
  group.ID == group_id
  peers := [peer | peer := group.Peers[_]; peer != input.peer_id]
}

# netbird_rules_from_groups returns a list of netbird rules for a given list of group names
rules_from_groups(groups, direction, action, port) := policies if {
  some group_name in groups
  peers := peers_from_group(group_name)
  policies := [
    get_rule(peer.ID, peer.IP, direction, action, port) |
    peer_id := peers[_]
    peer := input.peers[peer_id]
  ]
}
