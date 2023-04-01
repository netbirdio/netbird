package netbird

all[rule] {
    is_peer_in_any_group([{{range $i, $e := .All}}{{if $i}},{{end}}"{{$e}}"{{end}}])
    rule := {
        {{range $i, $e := .Destination}}rules_from_group("{{$e}}", "dst", "accept", ""),{{end}}
        {{range $i, $e := .Source}}rules_from_group("{{$e}}", "src", "accept", ""),{{end}}
    }[_][_]
}
