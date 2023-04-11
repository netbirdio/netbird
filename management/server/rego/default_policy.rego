package netbird

all[rule] {
    {{- if .Bidirect}}
    is_peer_in_any_group([{{range $i, $e := .All}}{{if $i}},{{end}}"{{$e}}"{{end}}])
    {{else}}
    is_peer_in_any_group([{{range $i, $e := .Sources}}{{if $i}},{{end}}"{{$e.Group}}"{{end}}])
    {{- end}}

    rule := {
        {{range .Destinations}}rules_from_group("{{.Group}}", "dst", "{{.Protocol}}", "{{.Ports}}", "{{.Action}}"),{{end}}
        {{- if .Bidirect}}
        {{range .Sources}}rules_from_group("{{.Group}}", "src", "{{.Protocol}}", "{{.Ports}}", "{{.Action}}"),{{end}}
        {{- end}}
    }[_][_]
}
