//go:build js

package certproof

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// CollectProofs proves nothing in a browser: it has no TPM, certificate store or file
// store to sign with, so the stores stay out of the WebAssembly build.
func CollectProofs(context.Context, []*proto.Checks, []byte, Config) []certposture.Proof {
	return nil
}

// UserContext identifies the user whose certificates a collection would include. A
// browser has no per-user store, so it never changes.
func UserContext(Config) string {
	return ""
}

// DefaultStore is empty in a browser.
func DefaultStore() Store {
	return Stores{}
}

func helperStore() Store {
	return DefaultStore()
}
