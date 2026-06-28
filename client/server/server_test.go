package server

import (
	"context"
	"net/url"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	daemonProto "github.com/netbirdio/netbird/client/proto"
)

func TestServer_Up(t *testing.T) {
	tempDir := t.TempDir()
	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origDefaultConfigPath := profilemanager.DefaultConfigPath
	profilemanager.ConfigDirOverride = tempDir
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	profilemanager.DefaultConfigPath = filepath.Join(tempDir, "default.json")
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
		profilemanager.DefaultConfigPath = origDefaultConfigPath
		profilemanager.ConfigDirOverride = ""
	})

	ctx := internal.CtxInitState(context.Background())

	currUser, err := user.Current()
	require.NoError(t, err)

	profName := "default"

	u, err := url.Parse("http://non-existent-url-for-testing.invalid:12345")
	require.NoError(t, err)

	ic := profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(tempDir, profName+".json"),
		ManagementURL: u.String(),
	}

	_, err = profilemanager.UpdateOrCreateConfig(ic)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	pm := profilemanager.ServiceManager{}
	err = pm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       profilemanager.ID(profName),
		Username: currUser.Username,
	})
	if err != nil {
		t.Fatalf("failed to set active profile state: %v", err)
	}

	s := New(ctx, "console", "", false, false, false, false)
	err = s.Start()
	require.NoError(t, err)

	upCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	upReq := &daemonProto.UpRequest{
		ProfileName: &profName,
		Username:    &currUser.Username,
	}
	_, err = s.Up(upCtx, upReq)
	log.Errorf("error from Up: %v", err)

	assert.Contains(t, err.Error(), "context deadline exceeded")
}

type mockSubscribeEventsServer struct {
	ctx        context.Context
	sentEvents []*daemonProto.SystemEvent
	grpc.ServerStream
}

func (m *mockSubscribeEventsServer) Send(event *daemonProto.SystemEvent) error {
	m.sentEvents = append(m.sentEvents, event)
	return nil
}

func (m *mockSubscribeEventsServer) Context() context.Context {
	return m.ctx
}

func TestServer_SubcribeEvents(t *testing.T) {
	tempDir := t.TempDir()
	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origDefaultConfigPath := profilemanager.DefaultConfigPath
	profilemanager.ConfigDirOverride = tempDir
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	profilemanager.DefaultConfigPath = filepath.Join(tempDir, "default.json")
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
		profilemanager.DefaultConfigPath = origDefaultConfigPath
		profilemanager.ConfigDirOverride = ""
	})

	ctx := internal.CtxInitState(context.Background())
	ic := profilemanager.ConfigInput{
		ConfigPath: tempDir + "/default.json",
	}

	_, err := profilemanager.UpdateOrCreateConfig(ic)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	currUser, err := user.Current()
	require.NoError(t, err)

	pm := profilemanager.ServiceManager{}
	err = pm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       "default",
		Username: currUser.Username,
	})
	if err != nil {
		t.Fatalf("failed to set active profile state: %v", err)
	}

	s := New(ctx, "console", "", false, false, false, false)

	err = s.Start()
	require.NoError(t, err)

	u, err := url.Parse("http://non-existent-url-for-testing.invalid:12345")
	require.NoError(t, err)
	s.config = &profilemanager.Config{
		ManagementURL: u,
	}

	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	upReq := &daemonProto.SubscribeRequest{}
	mockServer := &mockSubscribeEventsServer{
		ctx:          ctx,
		sentEvents:   make([]*daemonProto.SystemEvent, 0),
		ServerStream: nil,
	}
	err = s.SubscribeEvents(upReq, mockServer)

	assert.NoError(t, err)
}
