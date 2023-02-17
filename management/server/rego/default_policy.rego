peer_groups := groups if {
  groups := [name | group := input.group[_]
                    peer_id := group.peers[_] 
                    peer_id == input.peer_id
                    name := group.name]
}

peers := array.concat(sources, destinations) if {
  sources := [peer_id | group := peer_groups[_]
                        group == input.rules[_].source[_]
                        peer_id := group.peers]
  destinations := [peer_id | group := peer_groups[_]
                             group == input.rules[_].destinations[_]
                             peer_id := group.peers]
}
