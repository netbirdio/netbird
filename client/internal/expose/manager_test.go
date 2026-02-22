package expose

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonProto "github.com/netbirdio/netbird/client/proto"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestManager_Expose_Success(t *testing.T) {
	mock := &mgm.MockClient{
		CreateExposeFunc: func(ctx context.Context, req *mgmProto.ExposeServiceRequest) (*mgmProto.ExposeServiceResponse, error) {
			return &mgmProto.ExposeServiceResponse{
				ServiceName: "my-service",
				ServiceUrl:  "https://my-service.example.com",
				Domain:      "my-service.example.com",
			}, nil
		},
	}

	m := NewManager(mock)
	result, err := m.Expose(context.Background(), &mgmProto.ExposeServiceRequest{Port: 8080})
	require.NoError(t, err)
	assert.Equal(t, "my-service", result.ServiceName, "service name should match")
	assert.Equal(t, "https://my-service.example.com", result.ServiceURL, "service URL should match")
	assert.Equal(t, "my-service.example.com", result.Domain, "domain should match")
}

func TestManager_Expose_Error(t *testing.T) {
	mock := &mgm.MockClient{
		CreateExposeFunc: func(ctx context.Context, req *mgmProto.ExposeServiceRequest) (*mgmProto.ExposeServiceResponse, error) {
			return nil, errors.New("permission denied")
		},
	}

	m := NewManager(mock)
	_, err := m.Expose(context.Background(), &mgmProto.ExposeServiceRequest{Port: 8080})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied", "error should propagate")
}

func TestManager_Renew_Success(t *testing.T) {
	mock := &mgm.MockClient{
		RenewExposeFunc: func(ctx context.Context, domain string) error {
			assert.Equal(t, "my-service.example.com", domain, "domain should be passed through")
			return nil
		},
	}

	m := NewManager(mock)
	err := m.Renew(context.Background(), "my-service.example.com")
	require.NoError(t, err)
}

func TestManager_Renew_Timeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mock := &mgm.MockClient{
		RenewExposeFunc: func(ctx context.Context, domain string) error {
			return ctx.Err()
		},
	}

	m := NewManager(mock)
	err := m.Renew(ctx, "my-service.example.com")
	require.Error(t, err)
}

func TestManager_Stop_Success(t *testing.T) {
	mock := &mgm.MockClient{
		StopExposeFunc: func(ctx context.Context, domain string) error {
			assert.Equal(t, "my-service.example.com", domain, "domain should be passed through")
			return nil
		},
	}

	m := NewManager(mock)
	err := m.Stop(context.Background(), "my-service.example.com")
	require.NoError(t, err)
}

func TestManager_Stop_Error(t *testing.T) {
	mock := &mgm.MockClient{
		StopExposeFunc: func(ctx context.Context, domain string) error {
			return errors.New("not found")
		},
	}

	m := NewManager(mock)
	err := m.Stop(context.Background(), "my-service.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found", "error should propagate")
}

func TestNewManagementRequest(t *testing.T) {
	req := &daemonProto.ExposeServiceRequest{
		Port:       8080,
		Protocol:   daemonProto.ExposeProtocol_EXPOSE_HTTPS,
		Pin:        "1234",
		Password:   "secret",
		UserGroups: []string{"group1", "group2"},
		Domain:     "custom.example.com",
		NamePrefix: "my-prefix",
	}

	mgmReq := NewManagementRequest(req)

	assert.Equal(t, uint32(8080), mgmReq.Port, "port should match")
	assert.Equal(t, mgmProto.ExposeProtocol(daemonProto.ExposeProtocol_EXPOSE_HTTPS), mgmReq.Protocol, "protocol should match")
	assert.Equal(t, "1234", mgmReq.Pin, "pin should match")
	assert.Equal(t, "secret", mgmReq.Password, "password should match")
	assert.Equal(t, []string{"group1", "group2"}, mgmReq.UserGroups, "user groups should match")
	assert.Equal(t, "custom.example.com", mgmReq.Domain, "domain should match")
	assert.Equal(t, "my-prefix", mgmReq.NamePrefix, "name prefix should match")
}
