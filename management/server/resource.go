package server

type ResourceType string

const (
	host   ResourceType = "Host"
	subnet ResourceType = "Subnet"
	domain ResourceType = "Domain"
)

func (p ResourceType) String() string {
	return string(p)
}

type Resource struct {
	Type ResourceType
	ID   string
}
