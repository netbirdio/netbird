package types

// UpdateReason describes why an account peers update was triggered.
type UpdateReason struct {
	Resource  UpdateResource
	Operation UpdateOperation
}

// UpdateResource represents the kind of resource that triggered an account peers update.
type UpdateResource string

const (
	UpdateResourceAccountSettings UpdateResource = "account_settings"
	UpdateResourceDNSSettings     UpdateResource = "dns_settings"
	UpdateResourceGroup           UpdateResource = "group"
	UpdateResourceNameServerGroup UpdateResource = "nameserver_group"
	UpdateResourcePolicy          UpdateResource = "policy"
	UpdateResourcePostureCheck    UpdateResource = "posture_check"
	UpdateResourceRoute           UpdateResource = "route"
	UpdateResourceUser            UpdateResource = "user"
	UpdateResourcePeer            UpdateResource = "peer"
	UpdateResourceNetwork         UpdateResource = "network"
	UpdateResourceNetworkResource UpdateResource = "network_resource"
	UpdateResourceNetworkRouter   UpdateResource = "network_router"
	UpdateResourceService         UpdateResource = "service"
	UpdateResourceZone            UpdateResource = "zone"
	UpdateResourceZoneRecord      UpdateResource = "zone_record"
)

// UpdateOperation represents the kind of change that triggered the update.
type UpdateOperation string

const (
	UpdateOperationCreate UpdateOperation = "create"
	UpdateOperationUpdate UpdateOperation = "update"
	UpdateOperationDelete UpdateOperation = "delete"
)
