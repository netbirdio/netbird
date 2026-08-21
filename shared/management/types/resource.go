package types

type ResourceType string

const (
	ResourceTypePeer   ResourceType = "peer"
	ResourceTypeDomain ResourceType = "domain"
	ResourceTypeHost   ResourceType = "host"
	ResourceTypeSubnet ResourceType = "subnet"
)
