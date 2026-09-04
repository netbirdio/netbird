package agentnetwork

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	sharedplayground "github.com/netbirdio/netbird/shared/management/playground"
	"github.com/netbirdio/netbird/shared/management/status"
)

// PlaygroundPrincipal identifies the peer or synthetic group to emulate.
type PlaygroundPrincipal struct {
	Kind proxy.PlaygroundPrincipalKind
	ID   string
}

// PlaygroundRequest is a provider-native request executed with production effects.
type PlaygroundRequest struct {
	Principal PlaygroundPrincipal
	Method    string
	Path      string
	Headers   []proxy.AgentNetworkPlaygroundHeader
	Body      []byte
}

// PlaygroundResponse is the bounded live result returned by the selected proxy.
type PlaygroundResponse = proxy.AgentNetworkPlaygroundResponse

// ExecutePlayground resolves an emulated principal and dispatches one live request.
func (m *managerImpl) ExecutePlayground(
	ctx context.Context,
	accountID, operatorUserID string,
	req PlaygroundRequest,
) (*PlaygroundResponse, error) {
	if err := m.requirePermission(
		ctx,
		accountID,
		operatorUserID,
		modules.AgentNetworkProviders,
		operations.Create,
	); err != nil {
		return nil, err
	}

	switch req.Principal.Kind {
	case proxy.PlaygroundPrincipalPeer:
		if err := m.requirePermission(ctx, accountID, operatorUserID, modules.Peers, operations.Read); err != nil {
			return nil, err
		}
		if err := m.requirePermission(ctx, accountID, operatorUserID, modules.Users, operations.Read); err != nil {
			return nil, err
		}
	case proxy.PlaygroundPrincipalGroup:
		if err := m.requirePermission(ctx, accountID, operatorUserID, modules.Groups, operations.Read); err != nil {
			return nil, err
		}
	default:
		return nil, status.Errorf(status.InvalidArgument, "principal kind must be peer or group")
	}
	if strings.TrimSpace(req.Principal.ID) == "" {
		return nil, status.Errorf(status.InvalidArgument, "principal id is required")
	}

	headers := make(http.Header, len(req.Headers))
	for _, header := range req.Headers {
		headers[header.Name] = append(headers[header.Name], header.Values...)
	}
	if err := sharedplayground.ValidateRequest(req.Method, req.Path, headers, len(req.Body)); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "%s", err)
	}

	settings, ok, err := loadSettings(ctx, m.store, accountID)
	if err != nil {
		return nil, err
	}
	if !ok || strings.TrimSpace(settings.Endpoint()) == "" || strings.TrimSpace(settings.ProxyAddress) == "" {
		return nil, status.Errorf(status.PreconditionFailed, "agent network settings are not configured")
	}
	if m.proxyController == nil {
		return nil, status.Errorf(status.PreconditionFailed, "agent network proxy controller is not configured")
	}

	command := proxy.AgentNetworkPlaygroundRequest{
		PrincipalKind: req.Principal.Kind,
		PrincipalID:   req.Principal.ID,
		RequestID:     uuid.NewString(),
		AccountID:     accountID,
		Domain:        settings.Endpoint(),
		Method:        req.Method,
		Path:          req.Path,
		Headers:       clonePlaygroundHeaders(req.Headers),
		Body:          append([]byte(nil), req.Body...),
	}
	switch req.Principal.Kind {
	case proxy.PlaygroundPrincipalPeer:
		peer, err := m.store.GetPeerByID(
			ctx,
			store.LockingStrengthNone,
			accountID,
			req.Principal.ID,
		)
		if err != nil {
			return nil, err
		}
		groups, err := m.store.GetPeerGroups(
			ctx,
			store.LockingStrengthNone,
			accountID,
			peer.ID,
		)
		if err != nil {
			return nil, err
		}
		command.UserID = peer.ID
		command.UserEmail = peer.Name
		if peer.UserID != "" {
			user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, peer.UserID)
			if err != nil {
				return nil, err
			}
			if user.AccountID != accountID {
				return nil, status.Errorf(status.PermissionDenied, "peer owner is outside the account")
			}
			command.UserID = user.Id
			if user.Email != "" {
				command.UserEmail = user.Email
			}
		}
		command.GroupIDs = make([]string, 0, len(groups))
		command.GroupNames = make([]string, 0, len(groups))
		for _, group := range groups {
			command.GroupIDs = append(command.GroupIDs, group.ID)
			command.GroupNames = append(command.GroupNames, group.Name)
		}
	case proxy.PlaygroundPrincipalGroup:
		group, err := m.store.GetGroupByID(ctx, store.LockingStrengthNone, accountID, req.Principal.ID)
		if err != nil {
			return nil, err
		}
		command.GroupIDs = []string{group.ID}
		command.GroupNames = []string{group.Name}
	}

	return m.proxyController.ExecuteAgentNetworkPlayground(ctx, settings.ProxyAddress, command)
}

func clonePlaygroundHeaders(headers []proxy.AgentNetworkPlaygroundHeader) []proxy.AgentNetworkPlaygroundHeader {
	result := make([]proxy.AgentNetworkPlaygroundHeader, 0, len(headers))
	for _, header := range headers {
		result = append(result, proxy.AgentNetworkPlaygroundHeader{
			Name:   header.Name,
			Values: append([]string(nil), header.Values...),
		})
	}
	return result
}

func (*mockManager) ExecutePlayground(
	context.Context,
	string,
	string,
	PlaygroundRequest,
) (*PlaygroundResponse, error) {
	return &PlaygroundResponse{}, nil
}
