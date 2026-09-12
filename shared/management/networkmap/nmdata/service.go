package nmdata

// Service is the slim twin of the reverse-proxy service.Service. It carries
// only the state proxy-policy injection reads: the persisted reverse-proxy
// services and the in-memory ones synthesised from agent-network state, which
// are never written to the database.
type Service struct {
	ID           string
	Enabled      bool
	Private      bool
	Mode         string
	Domain       string
	ProxyCluster string
	AccessGroups []string
	Targets      []*ServiceTarget
}

// ServiceTarget is the slim twin of service.Target.
type ServiceTarget struct {
	Enabled    bool
	Path       string
	Port       uint16
	Protocol   string
	TargetID   string
	TargetType string
}
