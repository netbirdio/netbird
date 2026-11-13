package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

type fakeListProfilesClient struct {
	proto.DaemonServiceClient
	profiles []*proto.Profile
	err      error
}

func (f *fakeListProfilesClient) ListProfiles(_ context.Context, _ *proto.ListProfilesRequest, _ ...grpc.CallOption) (*proto.ListProfilesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &proto.ListProfilesResponse{Profiles: f.profiles}, nil
}

// The default profile keeps the ID "default" after a rename, so printing only
// the ID made `select work` report "default".
func TestSwitchedProfileLabelShowsRenamedDefaultName(t *testing.T) {
	client := &fakeListProfilesClient{profiles: []*proto.Profile{
		{Id: "default", Name: "work"},
		{Id: "a1b2c3d4e5f60718", Name: "home"},
	}}
	label := switchedProfileLabel(context.Background(), client, "celine", profilemanager.ID("default"))
	assert.Equal(t, "work (id: default)", label, "renamed default profile should show its name")
}

func TestSwitchedProfileLabelShowsNameAndShortID(t *testing.T) {
	client := &fakeListProfilesClient{profiles: []*proto.Profile{
		{Id: "default", Name: "work"},
		{Id: "a1b2c3d4e5f60718", Name: "home"},
	}}
	label := switchedProfileLabel(context.Background(), client, "celine", profilemanager.ID("a1b2c3d4e5f60718"))
	assert.Equal(t, "home (id: a1b2c3d4)", label, "label should carry the name and short ID")
}

func TestSwitchedProfileLabelStripsControlChars(t *testing.T) {
	client := &fakeListProfilesClient{profiles: []*proto.Profile{{Id: "a1b2c3d4e5f60718", Name: "ho\x1b[31mme"}}}
	label := switchedProfileLabel(context.Background(), client, "celine", profilemanager.ID("a1b2c3d4e5f60718"))
	assert.NotContains(t, label, "\x1b", "terminal escapes from the daemon must not reach the output")
}

func TestSwitchedProfileLabelFallsBackToID(t *testing.T) {
	id := profilemanager.ID("a1b2c3d4e5f60718")
	tests := []struct {
		name   string
		client *fakeListProfilesClient
	}{
		{
			name:   "lookup error",
			client: &fakeListProfilesClient{err: gstatus.Error(codes.Internal, "boom")},
		},
		{
			// The profile was removed between SwitchProfile and ListProfiles.
			name:   "profile not listed",
			client: &fakeListProfilesClient{profiles: []*proto.Profile{{Id: "default", Name: "work"}}},
		},
		{
			name:   "empty name",
			client: &fakeListProfilesClient{profiles: []*proto.Profile{{Id: id.String()}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			label := switchedProfileLabel(context.Background(), tc.client, "celine", id)
			assert.Equal(t, "id a1b2c3d4", label, "label should fall back to the short ID")
		})
	}
}
