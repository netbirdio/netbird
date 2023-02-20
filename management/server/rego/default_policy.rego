package netbird

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# get netbird peers IDs from the group but exclude current peer ID
peers_from_group(group_name) := peers if {
	some group in input.groups
    group.Name == group_name
    peers := [peer | peer := group.Peers[_]; peer != input.peer_id]
}

# get netbird policy object lists for given groups and set direction and action for that policies
policies_from_rule(groups, direction, action) := policies if {
  some group_name in groups
  peers := peers_from_group(group_name)
  policies := [{
    "ID": peer.ID,
    "IP": peer.IP,
    "Direction": direction,
    "Action": action,
    "Port": "",
    "Protocol": ""
  } | peer_id := peers[_]; peer := input.peers[peer_id]]
}

default_peers contains peers[_] if {
  some src_rule in input.src_rules
  src := policies_from_rule(src_rule.Destination, src_rule.Flow, "Allow")
  some dst_rule in input.dst_rules
  dst := policies_from_rule(dst_rule.Source, dst_rule.Flow, "Allow")
  peers := array.concat(src, dst)
}
