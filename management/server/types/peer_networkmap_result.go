package types

// PeerNetworkMapResult is what the network_map controller produces for a
// single peer. Exactly one of NetworkMap or Components is populated depending
// on the peer's capability:
//
//   - Components-capable peers (PeerCapabilityComponentNetworkMap) get
//     Components: the raw types.NetworkMapComponents the client decodes and
//     runs Calculate() on locally. NetworkMap stays nil — the server skips
//     the expansion entirely.
//   - Legacy peers (or any peer when the kill switch is set) get NetworkMap:
//     the fully-expanded view the legacy gRPC path consumes.
//
// The gRPC layer (ToSyncResponseForPeer) dispatches by which field is
// non-nil; callers must not rely on both being set.
type PeerNetworkMapResult struct {
	NetworkMap *NetworkMap
	Components *NetworkMapComponents
}

// IsComponents reports whether the result carries the components shape.
// Use this in preference to direct nil checks on the fields.
func (r PeerNetworkMapResult) IsComponents() bool {
	return r.Components != nil
}
