//go:build freebsd

package server

import "fmt"

// UInputInjector is a freebsd placeholder; the linux uinput implementation
// uses Linux-only ioctls (UI_DEV_CREATE etc.) and is not portable.
type UInputInjector struct {
	StubInputInjector
}

// NewUInputInjector always returns an error on freebsd so callers fall back
// to a stub or platform-appropriate injector.
func NewUInputInjector(_, _ int) (*UInputInjector, error) {
	return nil, fmt.Errorf("uinput not implemented on freebsd")
}
