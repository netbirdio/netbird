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

func TestDaemonActiveProfileForUserReturnsOwnProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "default", ProfileName: "default", Username: "root"}}
	prof, err := daemonActiveProfileForUser(context.Background(), client, "root")
	require.NoError(t, err)
	require.NotNil(t, prof)
	assert.Equal(t, profilemanager.ID("default"), prof.ID)
}

func TestDaemonActiveProfileForUserReturnsUnownedProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "default", ProfileName: "default", Username: ""}}
	prof, err := daemonActiveProfileForUser(context.Background(), client, "root")
	require.NoError(t, err)
	require.NotNil(t, prof)
	assert.Equal(t, profilemanager.ID("default"), prof.ID)
}

func TestDaemonActiveProfileForUserKeepsDaemonProfileOverStaleMirror(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "ab12", ProfileName: "work", Username: "misha"}}
	prof, err := daemonActiveProfileForUser(context.Background(), client, "misha")
	require.NoError(t, err)
	require.NotNil(t, prof)
	assert.Equal(t, profilemanager.ID("ab12"), prof.ID)
}

func TestDaemonActiveProfileForUserRejectsOtherUsersProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "ab12", ProfileName: "work", Username: "misha"}}
	prof, err := daemonActiveProfileForUser(context.Background(), client, "root")
	require.Error(t, err)
	assert.Nil(t, prof)
	assert.Contains(t, err.Error(), "--profile")
}

func TestDaemonActiveProfileForUserRejectsOtherUsersDefaultProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "default", ProfileName: "default", Username: "misha"}}
	prof, err := daemonActiveProfileForUser(context.Background(), client, "root")
	require.Error(t, err)
	assert.Nil(t, prof)
	assert.Contains(t, err.Error(), "--profile")
}

func TestDaemonActiveProfileForUserRejectsLookupError(t *testing.T) {
	client := &fakeActiveProfileClient{err: gstatus.Error(codes.Internal, "boom")}
	prof, err := daemonActiveProfileForUser(context.Background(), client, "root")
	require.Error(t, err)
	assert.Nil(t, prof)
	assert.Contains(t, err.Error(), "--profile")
}

func TestDaemonActiveProfileForUserRejectsEmptyResponse(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{}}
	prof, err := daemonActiveProfileForUser(context.Background(), client, "root")
	require.Error(t, err)
	assert.Nil(t, prof)
	assert.Contains(t, err.Error(), "--profile")
}

func TestDaemonActiveProfileForUserKeepsMirrorWhenDaemonWithoutRPC(t *testing.T) {
	client := &fakeActiveProfileClient{err: gstatus.Error(codes.Unimplemented, "unknown method")}
	prof, err := daemonActiveProfileForUser(context.Background(), client, "root")
	require.ErrorIs(t, err, errDaemonActiveProfileUnsupported)
	assert.Nil(t, prof)
}
