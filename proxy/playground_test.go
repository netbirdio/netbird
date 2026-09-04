package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	internalproxy "github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/playground"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type playgroundRecordingStream struct {
	grpc.ClientStream
	sent []*proto.SyncMappingsRequest
}

func (s *playgroundRecordingStream) Send(msg *proto.SyncMappingsRequest) error {
	s.sent = append(s.sent, msg)
	return nil
}

func (s *playgroundRecordingStream) Recv() (*proto.SyncMappingsResponse, error) {
	return nil, context.Canceled
}

func TestPlaygroundResponseWriterCapsAndSummarizesResponse(t *testing.T) {
	stream := &playgroundRecordingStream{}
	sender := &syncMappingsSender{stream: stream}
	writer := newPlaygroundResponseWriter(sender, "request-1", "account-1")
	writer.Header().Set("Content-Type", "text/event-stream")
	body := make([]byte, playground.MaxResponseBodyBytes+123)
	for i := range body {
		body[i] = byte(i)
	}

	written, err := writer.Write(body)
	require.NoError(t, err)
	assert.Equal(t, len(body), written, "Writer should drain bytes beyond the return cap")

	captured := internalproxy.NewCapturedData("access-log-request")
	captured.SetUserID("user-1")
	captured.SetUserEmail("user@example.com")
	captured.SetUserGroups([]string{"group-b", "group-a"})
	captured.SetUserGroupNames([]string{"Beta", "Alpha"})
	captured.SetMetadata(middleware.KeyLLMPolicyDecision, "allow")
	captured.SetMetadata(middleware.KeyLLMProvider, "openai")
	captured.SetMetadata(middleware.KeyLLMModel, "gpt-4o")
	captured.SetMetadata(middleware.KeyLLMResolvedProviderID, "provider-1")
	captured.SetMetadata(middleware.KeyLLMAuthorisingGroups, "group-a,group-b")
	captured.SetMetadata(middleware.KeyLLMRequestPrompt, "must not be returned")
	require.NoError(t, writer.finish(captured))

	require.NotEmpty(t, stream.sent)
	start := stream.sent[0].GetPlaygroundResponse()
	require.NotNil(t, start)
	assert.Equal(t, int32(http.StatusOK), start.GetStatusCode(), "First frame should carry HTTP status")
	assert.Equal(t, "text/event-stream", start.GetHeaders()[0].GetValues()[0], "First frame should carry response headers")

	bodyBytes := 0
	for _, message := range stream.sent[1 : len(stream.sent)-1] {
		frame := message.GetPlaygroundResponse()
		require.NotNil(t, frame)
		assert.LessOrEqual(t, len(frame.GetBodyChunk()), playground.ResponseChunkBytes, "Each frame should respect the chunk cap")
		bodyBytes += len(frame.GetBodyChunk())
	}
	assert.Equal(t, playground.MaxResponseBodyBytes, bodyBytes, "Only the bounded response prefix should be returned")

	terminal := stream.sent[len(stream.sent)-1].GetPlaygroundResponse()
	require.NotNil(t, terminal)
	assert.True(t, terminal.GetComplete(), "Last frame should be terminal")
	assert.True(t, terminal.GetBodyTruncated(), "Overflow should be marked truncated")
	assert.Equal(t, "user-1", terminal.GetUserId(), "Trusted identity should be returned")
	assert.Equal(t, []string{"group-a", "group-b"}, terminal.GetAuthorisingGroupIds(), "Only authorising groups should be summarized")
	assert.Equal(t, "enforcement_unavailable", terminal.GetPolicyReason(), "Missing policy attribution should be visible")
}

func TestExecutePlaygroundRejectsProtectedHeadersBeforeProxying(t *testing.T) {
	stream := &playgroundRecordingStream{}
	sender := &syncMappingsSender{stream: stream}
	server := &Server{}

	err := server.executeAgentNetworkPlayground(context.Background(), sender, &proto.AgentNetworkPlaygroundRequest{
		RequestId: "request-1",
		AccountId: "account-1",
		Method:    http.MethodGet,
		Path:      "/v1/models",
		Headers: []*proto.AgentNetworkPlaygroundHeader{
			{Name: "Authorization", Values: []string{"Bearer secret"}},
		},
	})

	require.NoError(t, err)
	require.Len(t, stream.sent, 2)
	assert.False(t, stream.sent[0].GetPlaygroundResponse().GetComplete(), "Validation failure should still begin a valid frame sequence")
	terminal := stream.sent[1].GetPlaygroundResponse()
	assert.True(t, terminal.GetComplete(), "Validation failure should terminate the sequence")
	assert.Contains(t, terminal.GetError(), "protected", "Protected header rejection should be actionable")
}

func TestCancelAllPlaygroundExecutionsClearsState(t *testing.T) {
	server := &Server{playgroundCancels: make(map[string]context.CancelFunc)}
	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	server.playgroundCancels["a"] = cancelA
	server.playgroundCancels["b"] = cancelB

	server.cancelAllAgentNetworkPlaygroundExecutions()

	assert.ErrorIs(t, ctxA.Err(), context.Canceled)
	assert.ErrorIs(t, ctxB.Err(), context.Canceled)
	assert.Empty(t, server.playgroundCancels, "Disconnect cleanup should remove all execution state")
}
