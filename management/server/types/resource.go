package types

import (
	"github.com/netbirdio/netbird/shared/management/http/api"
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
