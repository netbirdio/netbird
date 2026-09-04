package grpc

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/shared/management/playground"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type playgroundPending struct {
	accountID string
	frames    chan *proto.AgentNetworkPlaygroundResponse
	done      chan struct{}
}

// ExecuteAgentNetworkPlayground sends a live request to one capable proxy and
// waits for its correlated response frames.
func (s *ProxyServiceServer) ExecuteAgentNetworkPlayground(
	ctx context.Context,
	proxyIDs []string,
	request rpproxy.AgentNetworkPlaygroundRequest,
) (*rpproxy.AgentNetworkPlaygroundResponse, error) {
	if request.RequestID == "" || request.AccountID == "" {
		return nil, status.Error(codes.InvalidArgument, "request and account IDs are required")
	}

	conn, pending := s.registerPlaygroundRequest(proxyIDs, request.RequestID, request.AccountID)
	if conn == nil {
		return nil, status.Error(codes.Unavailable, "upgrade or connect a playground-capable proxy")
	}
	defer conn.unregisterPlaygroundRequest(request.RequestID, pending)

	if err := conn.sendSyncResponse(&proto.SyncMappingsResponse{
		PlaygroundRequest: playgroundRequestToProto(request),
	}); err != nil {
		return nil, status.Errorf(codes.Unavailable, "dispatch playground request: %v", err)
	}

	result := &rpproxy.AgentNetworkPlaygroundResponse{
		RequestID: request.RequestID,
		AccountID: request.AccountID,
	}
	started := false
	for {
		select {
		case <-ctx.Done():
			if err := conn.sendSyncResponse(&proto.SyncMappingsResponse{
				PlaygroundCancel: &proto.AgentNetworkPlaygroundCancel{
					RequestId: request.RequestID,
					AccountId: request.AccountID,
				},
			}); err != nil {
				log.WithContext(ctx).Debugf("send playground cancellation: %v", err)
			}
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-conn.ctx.Done():
			return nil, status.Error(codes.Unavailable, "playground proxy disconnected")
		case frame := <-pending.frames:
			complete, err := appendPlaygroundFrame(result, frame, &started)
			if err != nil {
				return nil, status.Errorf(codes.DataLoss, "playground response: %v", err)
			}
			if complete {
				return result, nil
			}
		}
	}
}

func (s *ProxyServiceServer) registerPlaygroundRequest(
	proxyIDs []string,
	requestID, accountID string,
) (*proxyConnection, *playgroundPending) {
	for _, proxyID := range proxyIDs {
		value, ok := s.connectedProxies.Load(proxyID)
		if !ok {
			continue
		}
		conn := value.(*proxyConnection)
		if !conn.supportsPlayground(accountID) {
			continue
		}
		pending, ok := conn.registerPlaygroundRequest(requestID, accountID)
		if ok {
			return conn, pending
		}
	}
	return nil, nil
}

func (conn *proxyConnection) supportsPlayground(accountID string) bool {
	if conn.syncStream == nil || conn.capabilities == nil ||
		conn.capabilities.SupportsAgentNetworkPlayground == nil ||
		!conn.capabilities.GetSupportsAgentNetworkPlayground() {
		return false
	}
	if conn.accountID != nil && *conn.accountID != accountID {
		return false
	}
	select {
	case <-conn.ctx.Done():
		return false
	default:
		return true
	}
}

func (conn *proxyConnection) registerPlaygroundRequest(
	requestID, accountID string,
) (*playgroundPending, bool) {
	conn.pendingMu.Lock()
	defer conn.pendingMu.Unlock()
	if !conn.playgroundReady {
		return nil, false
	}
	if _, exists := conn.pending[requestID]; exists {
		return nil, false
	}
	pending := &playgroundPending{
		accountID: accountID,
		frames:    make(chan *proto.AgentNetworkPlaygroundResponse),
		done:      make(chan struct{}),
	}
	conn.pending[requestID] = pending
	return pending, true
}

func (conn *proxyConnection) unregisterPlaygroundRequest(requestID string, pending *playgroundPending) {
	conn.pendingMu.Lock()
	if conn.pending[requestID] == pending {
		delete(conn.pending, requestID)
		close(pending.done)
	}
	conn.pendingMu.Unlock()
}

func (conn *proxyConnection) dispatchPlaygroundResponse(frame *proto.AgentNetworkPlaygroundResponse) bool {
	if frame == nil || frame.GetRequestId() == "" {
		return false
	}
	conn.pendingMu.Lock()
	pending := conn.pending[frame.GetRequestId()]
	conn.pendingMu.Unlock()
	if pending == nil || pending.accountID != frame.GetAccountId() {
		return false
	}
	select {
	case pending.frames <- frame:
		return true
	case <-pending.done:
		return false
	case <-conn.ctx.Done():
		return false
	}
}

func (conn *proxyConnection) sendSyncResponse(response *proto.SyncMappingsResponse) error {
	if conn.syncStream == nil {
		return fmt.Errorf("proxy is not using the bidirectional mapping stream")
	}
	conn.syncSendMu.Lock()
	defer conn.syncSendMu.Unlock()
	return conn.syncStream.Send(response)
}

func playgroundRequestToProto(request rpproxy.AgentNetworkPlaygroundRequest) *proto.AgentNetworkPlaygroundRequest {
	headers := make([]*proto.AgentNetworkPlaygroundHeader, 0, len(request.Headers))
	for _, header := range request.Headers {
		headers = append(headers, &proto.AgentNetworkPlaygroundHeader{
			Name:   header.Name,
			Values: append([]string(nil), header.Values...),
		})
	}
	return &proto.AgentNetworkPlaygroundRequest{
		RequestId:     request.RequestID,
		AccountId:     request.AccountID,
		PrincipalKind: string(request.PrincipalKind),
		PrincipalId:   request.PrincipalID,
		Domain:        request.Domain,
		UserId:        request.UserID,
		UserEmail:     request.UserEmail,
		GroupIds:      append([]string(nil), request.GroupIDs...),
		GroupNames:    append([]string(nil), request.GroupNames...),
		Method:        request.Method,
		Path:          request.Path,
		Headers:       headers,
		Body:          append([]byte(nil), request.Body...),
	}
}

func appendPlaygroundFrame(
	result *rpproxy.AgentNetworkPlaygroundResponse,
	frame *proto.AgentNetworkPlaygroundResponse,
	started *bool,
) (bool, error) {
	if frame == nil {
		return false, fmt.Errorf("empty frame")
	}
	if frame.GetRequestId() != result.RequestID || frame.GetAccountId() != result.AccountID {
		return false, fmt.Errorf("response correlation mismatch")
	}
	if !*started {
		if frame.GetComplete() || len(frame.GetBodyChunk()) != 0 {
			return false, fmt.Errorf("body or terminal frame received before start")
		}
		result.StatusCode = int(frame.GetStatusCode())
		result.Headers = playgroundHeadersFromProto(frame.GetHeaders())
		*started = true
		return false, nil
	}
	if frame.GetStatusCode() != 0 || len(frame.GetHeaders()) != 0 {
		return false, fmt.Errorf("duplicate start frame")
	}
	if len(result.Body)+len(frame.GetBodyChunk()) > playground.MaxResponseBodyBytes {
		return false, fmt.Errorf("body exceeds %d bytes", playground.MaxResponseBodyBytes)
	}
	result.Body = append(result.Body, frame.GetBodyChunk()...)
	if !frame.GetComplete() {
		return false, nil
	}
	if frame.GetError() != "" {
		return false, fmt.Errorf("proxy execution: %s", frame.GetError())
	}
	result.BodyTruncated = frame.GetBodyTruncated()
	result.UserID = frame.GetUserId()
	result.UserEmail = frame.GetUserEmail()
	result.GroupIDs = append([]string(nil), frame.GetGroupIds()...)
	result.GroupNames = append([]string(nil), frame.GetGroupNames()...)
	result.PolicyDecision = frame.GetPolicyDecision()
	result.PolicyReason = frame.GetPolicyReason()
	result.ProviderSurface = frame.GetProviderSurface()
	result.Model = frame.GetModel()
	result.ResolvedProviderID = frame.GetResolvedProviderId()
	result.AuthorisingGroupIDs = append([]string(nil), frame.GetAuthorisingGroupIds()...)
	result.SelectedPolicyID = frame.GetSelectedPolicyId()
	result.AttributionGroupID = frame.GetAttributionGroupId()
	return true, nil
}

func playgroundHeadersFromProto(headers []*proto.AgentNetworkPlaygroundHeader) []rpproxy.AgentNetworkPlaygroundHeader {
	result := make([]rpproxy.AgentNetworkPlaygroundHeader, 0, len(headers))
	for _, header := range headers {
		if header == nil {
			continue
		}
		result = append(result, rpproxy.AgentNetworkPlaygroundHeader{
			Name:   header.GetName(),
			Values: append([]string(nil), header.GetValues()...),
		})
	}
	return result
}
