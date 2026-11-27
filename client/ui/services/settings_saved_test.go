//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal/elevate"
	"github.com/netbirdio/netbird/client/proto"
)

type eventNameRecorder struct {
	names []string
}

func (e *eventNameRecorder) Emit(name string, _ ...any) bool {
	e.names = append(e.names, name)
	return true
}

type stubActiveProfileDaemon struct {
	stubDaemon
	active *proto.GetActiveProfileResponse
	asked  []*proto.GetConfigRequest
}

func (d *stubActiveProfileDaemon) GetActiveProfile(_ context.Context, _ *proto.GetActiveProfileRequest, _ ...grpc.CallOption) (*proto.GetActiveProfileResponse, error) {
	return d.active, nil
}

func (d *stubActiveProfileDaemon) GetConfig(_ context.Context, in *proto.GetConfigRequest, _ ...grpc.CallOption) (*proto.GetConfigResponse, error) {
	d.asked = append(d.asked, in)
	return d.stored, nil
}

func TestSetConfigAnnouncesASuccessfulSave(t *testing.T) {
	daemon := &stubDaemon{setConfig: func(*proto.SetConfigRequest) error { return nil }}
	emitter := &eventNameRecorder{}
	s := NewSettings(stubConn{client: daemon}, nil, nil, testDaemonAddr, emitter)

	disable := true
	outcome, err := s.SetConfig(context.Background(), SetConfigParams{
		ProfileName:         "default",
		DisableClientRoutes: &disable,
	})

	require.NoError(t, err)
	assert.False(t, outcome.Declined, "the save was not declined")
	assert.Equal(t, []string{EventSettingsSaved}, emitter.names, "a saved config should be announced once")
}

func TestSetConfigDoesNotAnnounceADeclinedSave(t *testing.T) {
	elev := &stubElevator{outcome: elevate.ErrDeclined, available: true}
	s, _ := settingsRefusingOnce(t, elev)
	emitter := &eventNameRecorder{}
	s.emitter = emitter

	outcome, err := s.SetConfig(context.Background(), SetConfigParams{
		ProfileName:   "default",
		ManagementURL: "https://mgmt.example.com",
	})

	require.NoError(t, err, "a declined prompt is not an error")
	assert.True(t, outcome.Declined, "nothing was applied")
	assert.Empty(t, emitter.names, "a declined save should not be announced")
}

func TestSetConfigDoesNotAnnounceARefusedSave(t *testing.T) {
	elev := &stubElevator{available: false}
	s, _ := settingsRefusingOnce(t, elev)
	emitter := &eventNameRecorder{}
	s.emitter = emitter

	_, err := s.SetConfig(context.Background(), SetConfigParams{
		ProfileName:   "default",
		ManagementURL: "https://mgmt.example.com",
	})

	require.Error(t, err, "the refusal is reported")
	assert.Empty(t, emitter.names, "a refused save should not be announced")
}

func TestClientRoutesDisabledReadsTheActiveProfile(t *testing.T) {
	for _, stored := range []bool{true, false} {
		daemon := &stubActiveProfileDaemon{
			stubDaemon: stubDaemon{stored: &proto.GetConfigResponse{DisableClientRoutes: stored}},
			active:     &proto.GetActiveProfileResponse{Id: "work-id", Username: "vma"},
		}
		s := NewSettings(stubConn{client: daemon}, nil, nil, testDaemonAddr, nil)

		disabled, err := s.ClientRoutesDisabled(context.Background())

		require.NoError(t, err)
		assert.Equal(t, stored, disabled, "the stored client routes setting should be returned")
		require.Len(t, daemon.asked, 1, "the config should be read once")
		assert.Equal(t, "work-id", daemon.asked[0].GetProfileName(), "the active profile's config should be read")
		assert.Equal(t, "vma", daemon.asked[0].GetUsername(), "the active profile's user should be passed")
	}
}
