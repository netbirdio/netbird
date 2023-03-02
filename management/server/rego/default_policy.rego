package netbird

# all rules for peer connectivity and firewall
all[rule] {
	is_peer_in_any_group([{{range $i, $e := .All}}{{if $i}},{{end}}"{{$e}}"{{end}}])
	rule := array.concat(
		rules_from_groups([{{range $i, $e := .Destination}}{{if $i}},{{end}}"{{$e}}"{{end}}], "dst", "accept", ""),
		rules_from_groups([{{range $i, $e := .Source}}{{if $i}},{{end}}"{{$e}}"{{end}}], "src", "accept", ""),
	)[_]
}
