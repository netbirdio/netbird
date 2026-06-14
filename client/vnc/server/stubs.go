//go:build !js && !ios && !android

package server

import (
	"fmt"
	"image"
)

// StubCapturer is a placeholder for platforms without screen capture support.
type StubCapturer struct{}

// Width returns 0 on unsupported platforms.
func (c *StubCapturer) Width() int { return 0 }

// Height returns 0 on unsupported platforms.
func (c *StubCapturer) Height() int { return 0 }

// Capture returns an error on unsupported platforms.
func (c *StubCapturer) Capture() (*image.RGBA, error) {
	return nil, fmt.Errorf("screen capture not supported on this platform")
}

// StubInputInjector is a placeholder for platforms without input injection support.
type StubInputInjector struct{}

// InjectKey is a no-op on unsupported platforms.
func (s *StubInputInjector) InjectKey(_ uint32, _ bool) {
	// no-op
}

// InjectKeyScancode is a no-op on unsupported platforms.
func (s *StubInputInjector) InjectKeyScancode(_ uint32, _ uint32, _ bool) {
	// no-op
}

// InjectPointer is a no-op on unsupported platforms.
func (s *StubInputInjector) InjectPointer(_ uint16, _, _, _, _ int) {
	// no-op
}

// SetClipboard is a no-op on unsupported platforms.
func (s *StubInputInjector) SetClipboard(_ string) {
	// no-op
}

// GetClipboard returns empty on unsupported platforms.
func (s *StubInputInjector) GetClipboard() string { return "" }

// TypeText is a no-op on unsupported platforms.
func (s *StubInputInjector) TypeText(_ string) {
	// no-op
}
