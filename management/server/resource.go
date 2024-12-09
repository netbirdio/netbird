package server

type ResourceType string

const (
	hostType   ResourceType = "Host"
	subnetType ResourceType = "Subnet"
	domainType ResourceType = "Domain"
)

func (p ResourceType) String() string {
	return string(p)
}

type Resource struct {
	Type ResourceType
	ID   string
}
