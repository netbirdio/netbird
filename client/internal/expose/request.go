package expose

import (
	daemonProto "github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// NewManagementRequest converts a daemon ExposeServiceRequest to a management ExposeServiceRequest.
func NewManagementRequest(req *daemonProto.ExposeServiceRequest) *mgmProto.ExposeServiceRequest {
	return &mgmProto.ExposeServiceRequest{
		Port:       req.Port,
		Protocol:   mgmProto.ExposeProtocol(req.Protocol),
		Pin:        req.Pin,
		Password:   req.Password,
		UserGroups: req.UserGroups,
		Domain:     req.Domain,
		NamePrefix: req.NamePrefix,
	}
}
