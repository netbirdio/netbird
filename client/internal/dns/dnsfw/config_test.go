package dnsfw

import (
	"reflect"
	"testing"
)

func TestBlockedPorts(t *testing.T) {
	tests := []struct {
		name     string
		disable  string
		ports    string
		setPorts bool
		want     []uint16
	}{
		{name: "default", want: defaultBlockedPorts},
		{name: "disabled", disable: "true", want: nil},
		{name: "disabled false keeps default", disable: "false", want: defaultBlockedPorts},
		{name: "override single port", ports: "53", setPorts: true, want: []uint16{53}},
		{name: "override multi", ports: "53, 853 ,5353", setPorts: true, want: []uint16{53, 853, 5353}},
		{name: "override empty disables", ports: "", setPorts: true, want: nil},
		{name: "override invalid skipped", ports: "53,not-a-port,853", setPorts: true, want: []uint16{53, 853}},
		{name: "override zero skipped", ports: "53,0,853", setPorts: true, want: []uint16{53, 853}},
		{name: "override only invalid disables", ports: "abc", setPorts: true, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvDisable, tc.disable)
			if tc.setPorts {
				t.Setenv(EnvPorts, tc.ports)
			}
			got := blockedPorts()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("blockedPorts() = %v, want %v", got, tc.want)
			}
		})
	}
}
