//go:build !windows && !ios && !android

package cmd

import (
	"errors"

	"github.com/kardianos/service"
)

// serviceState reports a service's state and whether it exists.
func serviceState(name string) (string, bool) {
	s, err := service.New(nil, &service.Config{Name: name})
	if err != nil {
		return "unknown", false
	}
	st, err := s.Status()
	switch {
	case errors.Is(err, service.ErrNotInstalled):
		return "", false
	case err != nil:
		return "unknown", true
	case st == service.StatusRunning:
		return "running", true
	case st == service.StatusStopped:
		return "stopped", true
	default:
		return "unknown", true
	}
}
