//go:build js

package main

import (
	"syscall/js"
	"testing"
)

// TestParseClientOptionsBooleans covers the boolean options against the value
// kinds a JS caller can pass: js.Value.Bool panics on anything but a boolean,
// so a wrong type has to be rejected before it reaches the client.
func TestParseClientOptionsBooleans(t *testing.T) {
	t.Run("unset leaves the lazy override empty", func(t *testing.T) {
		options, err := parseClientOptions(js.Global().Get("Object").New())
		if err != nil {
			t.Fatalf("parse options: %v", err)
		}
		if options.LazyConnectionEnabled != nil {
			t.Errorf("lazy override should stay unset, got %v", *options.LazyConnectionEnabled)
		}
		if options.DisableIPv6 {
			t.Error("disableIPv6 should default to false")
		}
	})

	t.Run("null defers to the management flag", func(t *testing.T) {
		jsOptions := js.Global().Get("Object").New()
		jsOptions.Set("lazyConnectionEnabled", js.Null())
		options, err := parseClientOptions(jsOptions)
		if err != nil {
			t.Fatalf("parse options: %v", err)
		}
		if options.LazyConnectionEnabled != nil {
			t.Errorf("lazy override should stay unset, got %v", *options.LazyConnectionEnabled)
		}
	})

	t.Run("booleans are carried through", func(t *testing.T) {
		jsOptions := js.Global().Get("Object").New()
		jsOptions.Set("lazyConnectionEnabled", false)
		jsOptions.Set("disableIPv6", true)
		options, err := parseClientOptions(jsOptions)
		if err != nil {
			t.Fatalf("parse options: %v", err)
		}
		if options.LazyConnectionEnabled == nil || *options.LazyConnectionEnabled {
			t.Errorf("lazy override should be false, got %v", options.LazyConnectionEnabled)
		}
		if !options.DisableIPv6 {
			t.Error("disableIPv6 should be true")
		}
	})

	t.Run("a non-boolean is rejected", func(t *testing.T) {
		for _, value := range []any{"true", 1, js.Global().Get("Object").New()} {
			jsOptions := js.Global().Get("Object").New()
			jsOptions.Set("lazyConnectionEnabled", value)
			if _, err := parseClientOptions(jsOptions); err == nil {
				t.Errorf("value %v should be rejected", value)
			}
		}
	})
}
