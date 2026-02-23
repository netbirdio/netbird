package expose

import (
	daemonProto "github.com/netbirdio/netbird/client/proto"
	mgm "github.com/netbirdio/netbird/shared/management/client"
)

// NewRequest converts a daemon ExposeServiceRequest to a management ExposeServiceRequest.
func NewRequest(req *daemonProto.ExposeServiceRequest) *Request {
	return &Request{
		Port:       uint16(req.Port),
		Protocol:   int(req.Protocol),
		Pin:        req.Pin,
		Password:   req.Password,
		UserGroups: req.UserGroups,
		Domain:     req.Domain,
		NamePrefix: req.NamePrefix,
	}
}

func toClientExposeRequest(Request Request) mgm.ExposeRequest {
	return mgm.ExposeRequest{
		NamePrefix: Request.NamePrefix,
		Domain:     Request.Domain,
		Port:       Request.Port,
		Protocol:   Request.Protocol,
		Pin:        Request.Pin,
		Password:   Request.Password,
		UserGroups: Request.UserGroups,
	}
}

func fromClientExposeResponse(response *mgm.ExposeResponse) *Response {
	return &Response{
		ServiceName: response.ServiceName,
		Domain:      response.Domain,
		ServiceURL:  response.ServiceURL,
	}
}
