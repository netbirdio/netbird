package server

type ResourceType string

const (
	// nolint
	hostType ResourceType = "Host"
	//nolint
	subnetType ResourceType = "Subnet"
	// nolint
	domainType ResourceType = "Domain"
)

func (p ResourceType) String() string {
	return string(p)
}

type Resource struct {
	Type ResourceType
	ID   string
}
