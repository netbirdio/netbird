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

func TestCheckRootProfileMatchAcceptsOwnProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "default", ProfileName: "default", Username: "root"}}
	err := checkRootProfileMatch(context.Background(), client, &profilemanager.Profile{ID: "default"}, "root")
	assert.NoError(t, err)
}

func TestCheckRootProfileMatchAcceptsUnownedProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "default", ProfileName: "default", Username: ""}}
	err := checkRootProfileMatch(context.Background(), client, &profilemanager.Profile{ID: "default"}, "root")
	assert.NoError(t, err)
}

func TestCheckRootProfileMatchRejectsOtherUsersProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "ab12", ProfileName: "work", Username: "misha"}}
	err := checkRootProfileMatch(context.Background(), client, &profilemanager.Profile{ID: "default"}, "root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--profile")
}

func TestCheckRootProfileMatchRejectsOtherUsersDefaultProfile(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{Id: "default", ProfileName: "default", Username: "misha"}}
	err := checkRootProfileMatch(context.Background(), client, &profilemanager.Profile{ID: "default"}, "root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--profile")
}

func TestCheckRootProfileMatchRejectsLookupError(t *testing.T) {
	client := &fakeActiveProfileClient{err: gstatus.Error(codes.Internal, "boom")}
	err := checkRootProfileMatch(context.Background(), client, &profilemanager.Profile{ID: "default"}, "root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--profile")
}

func TestCheckRootProfileMatchRejectsEmptyResponse(t *testing.T) {
	client := &fakeActiveProfileClient{resp: &proto.GetActiveProfileResponse{}}
	err := checkRootProfileMatch(context.Background(), client, &profilemanager.Profile{ID: "default"}, "root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--profile")
}

func TestCheckRootProfileMatchAllowsDaemonWithoutRPC(t *testing.T) {
	client := &fakeActiveProfileClient{err: gstatus.Error(codes.Unimplemented, "unknown method")}
	err := checkRootProfileMatch(context.Background(), client, &profilemanager.Profile{ID: "default"}, "root")
	assert.NoError(t, err)
}
