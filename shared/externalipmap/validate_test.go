package externalipmap

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	require.NotEmpty(t, ifaces, "host must have at least one interface")
	iface := ifaces[0].Name

	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{name: "nil", input: nil},
		{name: "single IP", input: []string{"203.0.113.5"}},
		{name: "IP to IP", input: []string{"203.0.113.5/10.0.0.5"}},
		{name: "IP to interface", input: []string{"203.0.113.5/" + iface}},
		{name: "several", input: []string{"203.0.113.5", "203.0.113.6/10.0.0.6"}},
		{name: "empty element", input: []string{""}, wantErr: true},
		// The engine rejects padded values, so validation must too.
		{name: "space padded", input: []string{"203.0.113.5", " 203.0.113.6"}, wantErr: true},
		{name: "not an IP", input: []string{"not-an-ip"}, wantErr: true},
		{name: "too many slashes", input: []string{"203.0.113.5/10.0.0.5/10.0.0.6"}, wantErr: true},
		{name: "unknown interface", input: []string{"203.0.113.5/nb-no-such-iface0"}, wantErr: true},
		{name: "external interface", input: []string{iface}, wantErr: true},
		{name: "interface to IP", input: []string{iface + "/10.0.0.5"}, wantErr: true},
		{name: "two interfaces", input: []string{iface + "/" + iface}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err, "input %q should be rejected", tt.input)
				return
			}
			assert.NoError(t, err, "input %q should be accepted", tt.input)
		})
	}
}
