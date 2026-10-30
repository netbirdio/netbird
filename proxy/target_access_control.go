package proxy

import (
	"fmt"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func parseTargetAccessActions(pathMappings []*proto.PathMapping) ([]proxy.AccessAction, bool, error) {
	actions := make([]proxy.AccessAction, len(pathMappings))
	strictPaths := false
	for i, pathMapping := range pathMappings {
		if pathMapping == nil {
			return nil, false, fmt.Errorf("nil target mapping")
		}
		action, err := targetAccessActionFromProto(pathMapping.GetAccessAction())
		if err != nil {
			return nil, false, err
		}
		actions[i] = action
		if action != proxy.AccessActionInherit {
			strictPaths = true
		}
	}
	return actions, strictPaths, nil
}

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
