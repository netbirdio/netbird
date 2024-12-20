package types

import (
	"github.com/netbirdio/netbird/management/server/http/api"
)

type Resource struct {
	ID   string
	Type string
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
	r.Type = string(req.Type)
}
