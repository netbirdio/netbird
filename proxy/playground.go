package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	proxyauth "github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	internalproxy "github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/playground"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type syncMappingsRequestStream interface {
	Send(*proto.SyncMappingsRequest) error
}

type syncMappingsSender struct {
	mu     sync.Mutex
	stream syncMappingsRequestStream
}

func (s *syncMappingsSender) Send(request *proto.SyncMappingsRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(request)
}

func (s *Server) startAgentNetworkPlaygroundExecution(
	streamCtx context.Context,
	sender *syncMappingsSender,
	req *proto.AgentNetworkPlaygroundRequest,
) {
	requestID := req.GetRequestId()
	if requestID == "" || req.GetAccountId() == "" {
		if err := s.sendAgentNetworkPlaygroundError(
			sender,
			requestID,
			req.GetAccountId(),
			"request and account IDs are required",
		); err != nil {
			s.Logger.Debugf("send invalid playground request response: %v", err)
		}
		return
	}

	execCtx, cancel := context.WithCancel(streamCtx)
	s.playgroundMu.Lock()
	if s.playgroundCancels == nil {
		s.playgroundCancels = make(map[string]context.CancelFunc)
	}
	if _, exists := s.playgroundCancels[requestID]; exists {
		s.playgroundMu.Unlock()
		cancel()
		s.Logger.Debugf("reject duplicate agent network playground request %s", requestID)
		return
	}
	s.playgroundCancels[requestID] = cancel
	s.playgroundMu.Unlock()

	go func() {
		defer cancel()
		defer s.removeAgentNetworkPlaygroundExecution(requestID)
		if err := s.executeAgentNetworkPlayground(execCtx, sender, req); err != nil && execCtx.Err() == nil {
			s.Logger.Debugf("agent network playground request %s: %v", requestID, err)
		}
	}()
}

func (s *Server) cancelAgentNetworkPlaygroundExecution(requestID string) {
	s.playgroundMu.Lock()
	cancel, ok := s.playgroundCancels[requestID]
	if ok {
		delete(s.playgroundCancels, requestID)
	}
	s.playgroundMu.Unlock()
	if ok {
		cancel()
	}
}

func (s *Server) removeAgentNetworkPlaygroundExecution(requestID string) {
	s.playgroundMu.Lock()
	delete(s.playgroundCancels, requestID)
	s.playgroundMu.Unlock()
}

func (s *Server) cancelAllAgentNetworkPlaygroundExecutions() {
	s.playgroundMu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.playgroundCancels))
	for requestID, cancel := range s.playgroundCancels {
		cancels = append(cancels, cancel)
		delete(s.playgroundCancels, requestID)
	}
	s.playgroundMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (s *Server) executeAgentNetworkPlayground(
	ctx context.Context,
	sender *syncMappingsSender,
	command *proto.AgentNetworkPlaygroundRequest,
) error {
	headers := playgroundHeadersToHTTP(command.GetHeaders())
	if err := playground.ValidateRequest(command.GetMethod(), command.GetPath(), headers, len(command.GetBody())); err != nil {
		return s.sendAgentNetworkPlaygroundError(sender, command.GetRequestId(), command.GetAccountId(), err.Error())
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/json")
	}

	req, err := http.NewRequestWithContext(
		ctx,
		command.GetMethod(),
		command.GetPath(),
		bytes.NewReader(command.GetBody()),
	)
	if err != nil {
		return s.sendAgentNetworkPlaygroundError(sender, command.GetRequestId(), command.GetAccountId(), fmt.Sprintf("create request: %v", err))
	}
	req.Header = headers
	req.Host = command.GetDomain()
	req.RemoteAddr = "127.0.0.1:0"
	req.RequestURI = command.GetPath()

	var captured *internalproxy.CapturedData
	identity := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = internalproxy.CapturedDataFromContext(r.Context())
		if captured == nil {
			http.Error(w, "playground identity context unavailable", http.StatusInternalServerError)
			return
		}
		captured.SetAccountID(types.AccountID(command.GetAccountId()))
		captured.SetUserID(command.GetUserId())
		captured.SetUserEmail(command.GetUserEmail())
		captured.SetUserGroups(command.GetGroupIds())
		captured.SetUserGroupNames(command.GetGroupNames())
		captured.SetAuthMethod(proxyauth.MethodPlayground.String())
		captured.SetAgentNetwork(true)
		s.proxy.ServeHTTP(w, r)
	})

	writer := newPlaygroundResponseWriter(sender, command.GetRequestId(), command.GetAccountId())
	handler := http.Handler(identity)
	handler = s.accessLog.Middleware(handler)
	handler = s.meter.Middleware(handler)
	handler.ServeHTTP(writer, req)

	if writer.err != nil {
		return writer.err
	}
	return writer.finish(captured)
}

func (s *Server) sendAgentNetworkPlaygroundError(
	sender *syncMappingsSender,
	requestID, accountID, message string,
) error {
	if err := sendPlaygroundFrame(sender, &proto.AgentNetworkPlaygroundResponse{
		RequestId: requestID,
		AccountId: accountID,
	}); err != nil {
		return err
	}
	return sendPlaygroundFrame(sender, &proto.AgentNetworkPlaygroundResponse{
		RequestId: requestID,
		AccountId: accountID,
		Complete:  true,
		Error:     message,
	})
}

func sendPlaygroundFrame(sender *syncMappingsSender, response *proto.AgentNetworkPlaygroundResponse) error {
	return sender.Send(&proto.SyncMappingsRequest{
		Msg: &proto.SyncMappingsRequest_PlaygroundResponse{
			PlaygroundResponse: response,
		},
	})
}

func playgroundHeadersToHTTP(headers []*proto.AgentNetworkPlaygroundHeader) http.Header {
	result := make(http.Header, len(headers))
	for _, header := range headers {
		if header == nil {
			continue
		}
		result[header.GetName()] = append([]string(nil), header.GetValues()...)
	}
	return result
}

type playgroundResponseWriter struct {
	sender     *syncMappingsSender
	requestID  string
	accountID  string
	header     http.Header
	wroteStart bool
	written    int
	truncated  bool
	err        error
}

func newPlaygroundResponseWriter(
	sender *syncMappingsSender,
	requestID, accountID string,
) *playgroundResponseWriter {
	return &playgroundResponseWriter{
		sender:    sender,
		requestID: requestID,
		accountID: accountID,
		header:    make(http.Header),
	}
}

func (w *playgroundResponseWriter) Header() http.Header {
	return w.header
}

func (w *playgroundResponseWriter) WriteHeader(statusCode int) {
	if w.wroteStart || w.err != nil {
		return
	}
	w.wroteStart = true
	w.err = sendPlaygroundFrame(w.sender, &proto.AgentNetworkPlaygroundResponse{
		RequestId:  w.requestID,
		AccountId:  w.accountID,
		StatusCode: int32(statusCode),
		Headers:    playgroundHeadersFromHTTP(w.header),
	})
}

func (w *playgroundResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteStart {
		w.WriteHeader(http.StatusOK)
	}
	if w.err != nil {
		return 0, w.err
	}

	remaining := playground.MaxResponseBodyBytes - w.written
	forward := len(p)
	if forward > remaining {
		forward = remaining
		w.truncated = true
	}
	for offset := 0; offset < forward; offset += playground.ResponseChunkBytes {
		end := offset + playground.ResponseChunkBytes
		if end > forward {
			end = forward
		}
		chunk := append([]byte(nil), p[offset:end]...)
		if err := sendPlaygroundFrame(w.sender, &proto.AgentNetworkPlaygroundResponse{
			RequestId: w.requestID,
			AccountId: w.accountID,
			BodyChunk: chunk,
		}); err != nil {
			w.err = err
			return offset, err
		}
	}
	w.written += forward
	if forward < len(p) {
		w.truncated = true
	}
	return len(p), nil
}

func (w *playgroundResponseWriter) Flush() {
	if !w.wroteStart {
		w.WriteHeader(http.StatusOK)
	}
}

func (w *playgroundResponseWriter) finish(captured *internalproxy.CapturedData) error {
	if !w.wroteStart {
		w.WriteHeader(http.StatusOK)
	}
	if w.err != nil {
		return w.err
	}

	response := &proto.AgentNetworkPlaygroundResponse{
		RequestId:     w.requestID,
		AccountId:     w.accountID,
		Complete:      true,
		BodyTruncated: w.truncated,
	}
	if captured == nil {
		response.Error = "playground identity context unavailable"
		return sendPlaygroundFrame(w.sender, response)
	}

	metadata := captured.GetMetadata()
	response.UserId = captured.GetUserID()
	response.UserEmail = captured.GetUserEmail()
	response.GroupIds = captured.GetUserGroups()
	response.GroupNames = captured.GetUserGroupNames()
	response.PolicyDecision = metadata[middleware.KeyLLMPolicyDecision]
	response.PolicyReason = metadata[middleware.KeyLLMPolicyReason]
	response.ProviderSurface = metadata[middleware.KeyLLMProvider]
	response.Model = metadata[middleware.KeyLLMModel]
	response.ResolvedProviderId = metadata[middleware.KeyLLMResolvedProviderID]
	response.AuthorisingGroupIds = splitPlaygroundMetadataList(metadata[middleware.KeyLLMAuthorisingGroups])
	response.SelectedPolicyId = metadata[middleware.KeyLLMSelectedPolicyID]
	response.AttributionGroupId = metadata[middleware.KeyLLMAttributionGroupID]
	if response.PolicyDecision == "allow" &&
		response.SelectedPolicyId == "" &&
		response.AttributionGroupId == "" &&
		response.Model != "" &&
		response.ResolvedProviderId != "" &&
		metadata[middleware.KeyLLMNonInference] != "true" {
		response.PolicyReason = "enforcement_unavailable"
	}
	return sendPlaygroundFrame(w.sender, response)
}

func playgroundHeadersFromHTTP(headers http.Header) []*proto.AgentNetworkPlaygroundHeader {
	result := make([]*proto.AgentNetworkPlaygroundHeader, 0, len(headers))
	for name, values := range headers {
		result = append(result, &proto.AgentNetworkPlaygroundHeader{
			Name:   name,
			Values: append([]string(nil), values...),
		})
	}
	return result
}

func splitPlaygroundMetadataList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
