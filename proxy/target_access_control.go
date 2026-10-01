package proxy

import (
	"fmt"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func targetAccessActionFromProto(action proto.TargetAccessAction) (proxy.AccessAction, error) {
	switch action {
	case proto.TargetAccessAction_TARGET_ACCESS_ACTION_INHERIT:
		return proxy.AccessActionInherit, nil
	case proto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS:
		return proxy.AccessActionBypass, nil
	case proto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK:
		return proxy.AccessActionBlock, nil
	default:
		return "", fmt.Errorf("unknown target access action %d", action)
	}
}
