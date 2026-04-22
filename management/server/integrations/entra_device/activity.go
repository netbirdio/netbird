package entra_device

import (
	"github.com/netbirdio/netbird/management/server/activity"
)

// Activity codes for this integration. We allocate well above the existing
// activity IDs to avoid colliding with future upstream codes.
const (
	PeerAddedWithEntraDevice           activity.Activity = 200
	EntraDeviceAuthCreated             activity.Activity = 201
	EntraDeviceAuthUpdated             activity.Activity = 202
	EntraDeviceAuthDeleted             activity.Activity = 203
	EntraDeviceAuthMappingCreated      activity.Activity = 204
	EntraDeviceAuthMappingUpdated      activity.Activity = 205
	EntraDeviceAuthMappingDeleted      activity.Activity = 206
	EntraDeviceAuthMappingRevoked      activity.Activity = 207
	GroupAddedToEntraDeviceMapping     activity.Activity = 208
	GroupRemovedFromEntraDeviceMapping activity.Activity = 209
)

func init() {
	activity.RegisterActivityMap(map[activity.Activity]activity.Code{
		PeerAddedWithEntraDevice: {
			Message: "Peer added via Entra device auth", Code: "peer.entra_device.add",
		},
		EntraDeviceAuthCreated: {
			Message: "Entra device auth integration created", Code: "entra_device_auth.create",
		},
		EntraDeviceAuthUpdated: {
			Message: "Entra device auth integration updated", Code: "entra_device_auth.update",
		},
		EntraDeviceAuthDeleted: {
			Message: "Entra device auth integration deleted", Code: "entra_device_auth.delete",
		},
		EntraDeviceAuthMappingCreated: {
			Message: "Entra device auth mapping created", Code: "entra_device_auth.mapping.create",
		},
		EntraDeviceAuthMappingUpdated: {
			Message: "Entra device auth mapping updated", Code: "entra_device_auth.mapping.update",
		},
		EntraDeviceAuthMappingDeleted: {
			Message: "Entra device auth mapping deleted", Code: "entra_device_auth.mapping.delete",
		},
		EntraDeviceAuthMappingRevoked: {
			Message: "Entra device auth mapping revoked", Code: "entra_device_auth.mapping.revoke",
		},
		GroupAddedToEntraDeviceMapping: {
			Message: "Group added to Entra device auth mapping", Code: "entra_device_auth.mapping.group.add",
		},
		GroupRemovedFromEntraDeviceMapping: {
			Message: "Group removed from Entra device auth mapping", Code: "entra_device_auth.mapping.group.delete",
		},
	})
}
