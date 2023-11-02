package iface

type MobileIFaceArguments struct {
	Routes        []string
	Dns           string
	SearchDomains []string
}

// NetInterface represents a generic network tunnel interface
type NetInterface interface {
	Close() error
}
