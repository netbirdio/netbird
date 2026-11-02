package service

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// TargetAccessAction controls authentication for a selected HTTP target.
type TargetAccessAction string

const (
	TargetAccessActionInherit TargetAccessAction = "inherit"
	TargetAccessActionBypass  TargetAccessAction = "bypass"
	TargetAccessActionBlock   TargetAccessAction = "block"
)

func (t *Target) effectiveAccessAction() TargetAccessAction {
	if t.AccessAction == "" {
		return TargetAccessActionInherit
	}
	return t.AccessAction
}

func targetAccessActionToProto(action TargetAccessAction) proto.TargetAccessAction {
	switch action {
	case TargetAccessActionInherit:
		return proto.TargetAccessAction_TARGET_ACCESS_ACTION_INHERIT
	case TargetAccessActionBypass:
		return proto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS
	case TargetAccessActionBlock:
		return proto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK
	default:
		return proto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK
	}
}

// HasTargetAccessControl reports whether any target overrides service authentication.
func (s *Service) HasTargetAccessControl() bool {
	for _, target := range s.Targets {
		if target != nil && target.effectiveAccessAction() != TargetAccessActionInherit {
			return true
		}
	}
	return false
}

func validateTargetAccessAction(idx int, target *Target, private bool) error {
	action, err := validatedTargetAccessAction(idx, target)
	if err != nil {
		return err
	}
	if action == TargetAccessActionBypass {
		if private {
			return fmt.Errorf("target %d: bypass access_action is not supported for private services", idx)
		}
		if target.Options.AgentNetwork {
			return fmt.Errorf("target %d: bypass access_action is not supported for Agent Network targets", idx)
		}
	}

	if action == TargetAccessActionInherit {
		return nil
	}
	return validateAccessActionPath(idx, target.Path)
}

func validatedTargetAccessAction(idx int, target *Target) (TargetAccessAction, error) {
	if target.AccessActionProvided && target.AccessAction == "" {
		return "", fmt.Errorf("target %d: unknown access_action %q", idx, target.AccessAction)
	}
	action := target.effectiveAccessAction()
	switch action {
	case TargetAccessActionInherit, TargetAccessActionBypass, TargetAccessActionBlock:
		return action, nil
	default:
		return "", fmt.Errorf("target %d: unknown access_action %q", idx, target.AccessAction)
	}
}

func normalizedTargetPath(configured *string) string {
	if configured == nil || *configured == "" {
		return "/"
	}
	return *configured
}

func validateAccessActionPath(idx int, configured *string) error {
	if configured == nil {
		return nil
	}
	value := *configured
	if value == "" {
		return nil
	}
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("target %d: access_action path %q must start with /", idx, value)
	}
	if !utf8.ValidString(value) || strings.ContainsAny(value, "%\\?#;") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("target %d: access_action path %q contains invalid characters", idx, value)
	}
	segments := strings.Split(strings.TrimPrefix(value, "/"), "/")
	for i, segment := range segments {
		if segment == "." || segment == ".." {
			return fmt.Errorf("target %d: access_action path %q is not canonical", idx, value)
		}
		if segment == "" && value != "/" && i != len(segments)-1 {
			return fmt.Errorf("target %d: access_action path %q is not canonical", idx, value)
		}
	}
	return nil
}
