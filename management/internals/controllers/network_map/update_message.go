package network_map

import (
	"github.com/netbirdio/netbird/shared/management/proto"
)

type UpdateMessage struct {
	Update *proto.SyncResponse
}
