package types

import (
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type ResourceType string

const (
	ResourceTypePeer   ResourceType = "peer"
	ResourceTypeDomain ResourceType = "domain"
	ResourceTypeHost   ResourceType = "host"
	ResourceTypeSubnet ResourceType = "subnet"
)

type Resource struct {
	ID   string
	Type ResourceType
}

func (r *Resource) ToAPIResponse() *api.Resource {
	if r.ID == "" && r.Type == "" {
		return nil
	}

	return &api.Resource{
		Id:   r.ID,
		Type: api.ResourceType(r.Type),
	}
}

func (r *Resource) FromAPIRequest(req *api.Resource) {
	if req == nil {
		return
	}

	r.ID = req.Id
	r.Type = ResourceType(req.Type)
}
