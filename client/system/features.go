package system

// Phase 3.7i (#5989): keywords this client build implements that the
// management server may want to know about. Sent in
// PeerSystemMeta.SupportedFeatures on every Login/Sync.
//
// Adding a new keyword:
//  1. Append it here (new entries at the end so test diffs stay small).
//  2. Update the test in features_test.go.
//  3. Add the server-side branch that consumes it (typically in
//     management/internals/shared/grpc/conversion.go) or document
//     explicitly that none is needed.
//
// Removing a keyword: only safe if no live management server still
// branches on it. Coordinate with the mgmt-server release.
var supportedFeatures = []string{
	"p2p_dynamic",
}

// SupportedFeatures returns the list of capability keywords this build
// advertises. Returns a fresh slice so callers cannot mutate the
// underlying global list.
func SupportedFeatures() []string {
	out := make([]string, len(supportedFeatures))
	copy(out, supportedFeatures)
	return out
}
