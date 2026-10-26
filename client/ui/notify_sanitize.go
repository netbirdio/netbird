//go:build !android && !ios && !freebsd && !js

package main

import (
	"runtime"
	"strings"
	"unicode"

	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

// sanitizeNotification restricts toast text to a safe character set on Windows.
// When the COM toast fails, the backend renders the toast into a PowerShell
// here-string where $(...), $var and backtick sequences are evaluated, and the
// text includes values chosen by management such as route names. Other
// platforms pass the text to the OS as data.
func sanitizeNotification(opts notifications.NotificationOptions) notifications.NotificationOptions {
	if runtime.GOOS != "windows" {
		return opts
	}
	opts.Title = sanitizeToastText(opts.Title)
	opts.Subtitle = sanitizeToastText(opts.Subtitle)
	opts.Body = sanitizeToastText(opts.Body)
	return opts
}

// sanitizeToastText keeps letters, marks, numbers, punctuation and spaces and
// replaces every other rune with '?'. That excludes the PowerShell expansion
// characters ($ and the backtick) without having to enumerate them. Line breaks
// and tabs become spaces so the text stays on one line.
func sanitizeToastText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			return ' '
		case unicode.IsLetter(r), unicode.IsMark(r), unicode.IsNumber(r),
			unicode.IsPunct(r), unicode.Is(unicode.Zs, r):
			return r
		}
		return '?'
	}, s)
}
