package types

// DiscoveredModel is a normalized model identifier returned by a provider's
// persisted upstream endpoint. Discovery does not persist models; the caller
// must explicitly update the provider to opt into the returned list.
type DiscoveredModel struct {
	ID    string
	Label string
}

// ModelDiscoveryResult describes a successful proxy-executed discovery probe.
// RequestID correlates the management request with the proxy control message,
// and ProxyCluster identifies the network vantage point that ran it.
type ModelDiscoveryResult struct {
	RequestID    string
	Source       string
	ProxyCluster string
	Models       []DiscoveredModel
}
