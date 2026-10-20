package nmdata

// NetworkRouter is the slim twin of routers/types.NetworkRouter.
type NetworkRouter struct {
	PublicID   string
	PeerGroups []string
	Masquerade bool
	Metric     int
	Enabled    bool
}
