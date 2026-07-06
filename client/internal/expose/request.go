package expose

import (
	daemonProto "github.com/netbirdio/netbird/client/proto"
	mgm "github.com/netbirdio/netbird/shared/management/client"
)

// NewRequest converts a daemon ExposeServiceRequest to a management ExposeServiceRequest.
func NewRequest(req *daemonProto.ExposeServiceRequest) *Request {
	return &Request{
		Port:               uint16(req.Port),
		Protocol:           ProtocolType(req.Protocol),
		Pin:                req.Pin,
		Password:           req.Password,
		UserGroups:         req.UserGroups,
		Domain:             req.Domain,
		NamePrefix:         req.NamePrefix,
		ListenPort:         uint16(req.ListenPort),
		AccessRestrictions: toClientAccessRestrictions(req.AccessRestrictions),
	}
}

func toClientExposeRequest(req Request) mgm.ExposeRequest {
	return mgm.ExposeRequest{
		NamePrefix:         req.NamePrefix,
		Domain:             req.Domain,
		Port:               req.Port,
		Protocol:           int(req.Protocol),
		Pin:                req.Pin,
		Password:           req.Password,
		UserGroups:         req.UserGroups,
		ListenPort:         req.ListenPort,
		AccessRestrictions: req.AccessRestrictions,
	}
}

func toClientAccessRestrictions(r *daemonProto.ExposeAccessRestrictions) *mgm.ExposeAccessRestrictions {
	if r == nil {
		return nil
	}
	return &mgm.ExposeAccessRestrictions{
		AllowedCIDRs:     append([]string(nil), r.AllowedCidrs...),
		BlockedCIDRs:     append([]string(nil), r.BlockedCidrs...),
		AllowedCountries: append([]string(nil), r.AllowedCountries...),
		BlockedCountries: append([]string(nil), r.BlockedCountries...),
	}
}

func fromClientExposeResponse(response *mgm.ExposeResponse) *Response {
	return &Response{
		ServiceName:      response.ServiceName,
		Domain:           response.Domain,
		ServiceURL:       response.ServiceURL,
		PortAutoAssigned: response.PortAutoAssigned,
	}
}
