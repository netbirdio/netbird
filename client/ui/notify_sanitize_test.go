//go:build !android && !ios && !freebsd && !js

package main

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
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
		{name: "control characters are replaced", in: "a\r\n\"@\n\tb\x00c", want: "a  ?@  b?c"},
		{name: "here-string terminator", in: "\"@Remove-Item C:\\x", want: "?@Remove-Item C:\\x"},
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
	assert.NotContains(t, got, "\"", "double quote is needed to terminate a PowerShell here-string")
}

func TestSanitizeNotification(t *testing.T) {
	in := notifications.NotificationOptions{
		ID:       "id-$(calc)",
		Title:    "t $(calc)",
		Subtitle: "s `calc`",
		Body:     "b $env:USERNAME",
	}

	got := sanitizeNotification(in)

	assert.Equal(t, in.ID, got.ID, "ID is not rendered and must be left alone")
	if runtime.GOOS != "windows" {
		assert.Equal(t, in, got, "text must pass through untouched off Windows")
		return
	}
	assert.Equal(t, "t ?(calc)", got.Title)
	assert.Equal(t, "s ?calc?", got.Subtitle)
	assert.Equal(t, "b ?env:USERNAME", got.Body)
}
