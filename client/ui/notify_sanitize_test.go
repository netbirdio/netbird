//go:build !android && !ios && !freebsd && !js

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeToastText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain text is untouched", in: "Exit node connected. ID: exit-1", want: "Exit node connected. ID: exit-1"},
		{name: "unicode is untouched", in: "Ausgangsknoten über Büro", want: "Ausgangsknoten über Büro"},
		{name: "subexpression", in: "ID: $(calc)", want: "ID: ?(calc)"},
		{name: "variable expansion", in: "ID: $env:USERNAME", want: "ID: ?env:USERNAME"},
		{name: "backtick escape", in: "a`$(calc)", want: "a??(calc)"},
		{name: "control characters are replaced", in: "a\r\n\"@\nb\x00c", want: "a  \"@ b?c"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeToastText(tc.in))
		})
	}
}

func TestSanitizeToastTextHasNoPowerShellMetacharacters(t *testing.T) {
	got := sanitizeToastText("$(calc) `x` ${y} $z\n@\"")
	assert.NotContains(t, got, "$", "dollar sign would expand inside a PowerShell here-string")
	assert.NotContains(t, got, "`", "backtick escapes inside a PowerShell here-string")
	assert.NotContains(t, got, "\n", "newline could terminate a PowerShell here-string")
}
