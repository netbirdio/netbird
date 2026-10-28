package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAcceptEnv(t *testing.T) {
	tests := []struct {
		envVar string
		want   bool
	}{
		{"LANG=en_US.UTF-8", true},
		{"LANGUAGE=de:en", true},
		{"LC_ALL=C.UTF-8", true},
		{"LC_MESSAGES=de_DE.UTF-8@euro", true},
		{"TERM=xterm-256color", true},
		{"COLORTERM=truecolor", true},
		{"TZ=Europe/Berlin", true},
		{"TZ=:Europe/Berlin", true},
		{"TZ=CET-1CEST,M3.5.0,M10.5.0/3", true},
		{"EDITOR=/usr/bin/vim", true},
		{"LANG", true},

		{"LD_PRELOAD=/tmp/x.so", false},
		{"PATH=/tmp", false},
		{"=LANG", false},

		// values naming files must not reach login/su, which run as root
		{"LANGUAGE=../../../../tmp/catalogs", false},
		{"LANGUAGE=de:../../../../tmp/catalogs", false},
		{"LANG=/tmp/locale", false},
		{"LC_MESSAGES=../x", false},
		{"LC_ALL=%n", false},
		{"TERM=../../tmp/terminfo", false},
		{"COLORTERM=/tmp/x", false},
		{"TZ=/etc/shadow", false},
		{"TZ=:/etc/shadow", false},
		{"TZ=../../../etc/shadow", false},
		{"TZ=Europe/../../../../etc/shadow", false},

		// a bare ".." is a path component on its own, with no "/" needed to traverse
		{"LANG=..", false},
		{"LANGUAGE=..", false},
		{"TERM=..", false},
		{"COLORTERM=..", false},
		{"LC_ALL=..", false},
	}

	for _, tt := range tests {
		t.Run(tt.envVar, func(t *testing.T) {
			assert.Equal(t, tt.want, acceptEnv(tt.envVar))
		})
	}
}
