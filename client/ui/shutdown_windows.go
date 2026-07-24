//go:build windows

package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ui/services"
)

const (
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
)

func endSessionInterceptor() func(hwnd uintptr, msg uint32, wParam, lParam uintptr) (uintptr, bool) {
	return func(_ uintptr, msg uint32, wParam, _ uintptr) (uintptr, bool) {
		switch msg {
		case wmQueryEndSession:
			services.BeginSessionEnd()
			return 1, true
		case wmEndSession:
			if wParam == 0 {
				services.AbortSessionEnd()
				return 0, true
			}
			log.Info("windows session is ending; exiting immediately")
			os.Exit(0)
			return 0, true
		default:
			return 0, false
		}
	}
}
