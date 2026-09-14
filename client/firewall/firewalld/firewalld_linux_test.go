//go:build linux

package firewalld

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestDBusErrContains(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
		want bool
	}{
		{"nil error", nil, errZoneAlreadySet, false},
		{"plain error match", errors.New("ZONE_ALREADY_SET: wt0"), errZoneAlreadySet, true},
		{"plain error miss", errors.New("something else"), errZoneAlreadySet, false},
		{
			"dbus.Error body match",
			dbus.Error{Name: "org.fedoraproject.FirewallD1.Exception", Body: []any{"ZONE_ALREADY_SET: wt0"}},
			errZoneAlreadySet,
			true,
		},
		{
			"dbus.Error body miss",
			dbus.Error{Name: "org.fedoraproject.FirewallD1.Exception", Body: []any{"INVALID_INTERFACE"}},
			errAlreadyEnabled,
			false,
		},
		{
			"dbus.Error non-string body falls back to Error()",
			dbus.Error{Name: "x", Body: []any{123}},
			"x",
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dbusErrContains(tc.err, tc.code)
			if got != tc.want {
				t.Fatalf("dbusErrContains(%v, %q) = %v; want %v", tc.err, tc.code, got, tc.want)
			}
		})
	}
}
