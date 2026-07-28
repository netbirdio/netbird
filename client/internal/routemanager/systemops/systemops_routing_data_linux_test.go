//go:build linux && !android

package systemops

// Interface names used by the shared routing test fixtures. Kept untagged (no
// privileged build tag) so the non-privileged test files in this package compile.
//
//nolint:unused // consumed by the privileged-tagged routing tests
var expectedVPNint = "wgtest0"

//nolint:unused // consumed by the privileged-tagged routing tests
var expectedExternalInt = "dummyext0"

//nolint:unused // consumed by the privileged-tagged routing tests
var expectedInternalInt = "dummyint0"
