package netbird

all[rule] {
    is_peer_in_any_group([{{range $i, $e := .All}}{{if $i}},{{end}}"{{$e}}"{{end}}])
    rule := {
        {{range .Destinations}}rules_from_group("{{.Group}}", "dst", "{{.Protocol}}", "{{.Ports}}", "{{.Action}}"),{{end}}
        {{range .Sources}}rules_from_group("{{.Group}}", "src", "{{.Protocol}}", "{{.Ports}}", "{{.Action}}"),{{end}}
    }[_][_]
}
