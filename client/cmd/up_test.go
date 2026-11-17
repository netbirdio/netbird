package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

type fakeActiveProfileClient struct {
	proto.DaemonServiceClient
	resp *proto.GetActiveProfileResponse
	err  error
}

func (f *fakeActiveProfileClient) GetActiveProfile(_ context.Context, _ *proto.GetActiveProfileRequest, _ ...grpc.CallOption) (*proto.GetActiveProfileResponse, error) {
	return f.resp, f.err
}

func TestDaemonActiveProfileReturnsDaemonProfileOverStaleMirror(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "ab12", ProfileName: "work"}}
	prof, err := daemonActiveProfile(context.Background(), client)
	require.NoError(t, err)
	require.NotNil(t, prof)
	assert.Equal(t, profilemanager.ID("ab12"), prof.ID)
}

// Root brings up whatever the daemon has active, so a profile another user
// owns is not refused.
func TestDaemonActiveProfileReturnsOtherUsersProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "ab12", ProfileName: "work", Username: "misha"}}
	prof, err := daemonActiveProfile(context.Background(), client)
	require.NoError(t, err)
	require.NotNil(t, prof)
	assert.Equal(t, profilemanager.ID("ab12"), prof.ID)
}

func TestDaemonActiveProfileRejectsLookupError(t *testing.T) {
	client := &fakeActiveProfileClient{err: gstatus.Error(codes.Internal, "boom")}
	prof, err := daemonActiveProfile(context.Background(), client)
	require.Error(t, err)
	assert.Nil(t, prof)
	assert.Contains(t, err.Error(), "--profile")
}

func TestDaemonActiveProfileRejectsEmptyResponse(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{}}
	prof, err := daemonActiveProfile(context.Background(), client)
	require.Error(t, err)
	assert.Nil(t, prof)
	assert.Contains(t, err.Error(), "--profile")
}

func TestDaemonActiveProfileKeepsMirrorWhenDaemonWithoutRPC(t *testing.T) {
	client := &fakeActiveProfileClient{err: gstatus.Error(codes.Unimplemented, "unknown method")}
	prof, err := daemonActiveProfile(context.Background(), client)
	require.ErrorIs(t, err, errDaemonActiveProfileUnsupported)
	assert.Nil(t, prof)
}
