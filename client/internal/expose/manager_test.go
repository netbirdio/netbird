package expose

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonProto "github.com/netbirdio/netbird/client/proto"
	mgm "github.com/netbirdio/netbird/shared/management/client"
)

func TestManager_Expose_Success(t *testing.T) {
	mock := &mgm.MockClient{
		CreateExposeFunc: func(ctx context.Context, req mgm.ExposeRequest) (*mgm.ExposeResponse, error) {
			return &mgm.ExposeResponse{
				ServiceName: "my-service",
				ServiceURL:  "https://my-service.example.com",
				Domain:      "my-service.example.com",
			}, nil
		},
	}

	m := NewManager(context.Background(), mock)
	result, err := m.Expose(context.Background(), Request{Port: 8080})
	require.NoError(t, err)
	assert.Equal(t, "my-service", result.ServiceName, "service name should match")
	assert.Equal(t, "https://my-service.example.com", result.ServiceURL, "service URL should match")
	assert.Equal(t, "my-service.example.com", result.Domain, "domain should match")
}

func TestManager_Expose_Error(t *testing.T) {
	mock := &mgm.MockClient{
		CreateExposeFunc: func(ctx context.Context, req mgm.ExposeRequest) (*mgm.ExposeResponse, error) {
			return nil, errors.New("permission denied")
		},
	}

	m := NewManager(context.Background(), mock)
	_, err := m.Expose(context.Background(), Request{Port: 8080})
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

	m := NewManager(context.Background(), mock)
	err := m.renew(context.Background(), "my-service.example.com")
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

	m := NewManager(ctx, mock)
	err := m.renew(ctx, "my-service.example.com")
	require.Error(t, err)
}

func TestToClientExposeRequestCopiesAccessRestrictions(t *testing.T) {
	req := Request{
		Port:     8080,
		Protocol: ProtocolHTTPS,
		AccessRestrictions: &mgm.ExposeAccessRestrictions{
			AllowedCIDRs:     []string{"35.231.147.226/32"},
			BlockedCIDRs:     []string{"198.51.100.0/24"},
			AllowedCountries: []string{"US"},
			BlockedCountries: []string{"RU"},
		},
	}

	got := toClientExposeRequest(req)
	require.NotNil(t, got.AccessRestrictions)
	assert.Equal(t, []string{"35.231.147.226/32"}, got.AccessRestrictions.AllowedCIDRs)
	assert.Equal(t, []string{"198.51.100.0/24"}, got.AccessRestrictions.BlockedCIDRs)
	assert.Equal(t, []string{"US"}, got.AccessRestrictions.AllowedCountries)
	assert.Equal(t, []string{"RU"}, got.AccessRestrictions.BlockedCountries)
}

func TestNewRequest(t *testing.T) {
	req := &daemonProto.ExposeServiceRequest{
		Port:       8080,
		Protocol:   daemonProto.ExposeProtocol_EXPOSE_HTTPS,
		Pin:        "123456",
		Password:   "secret",
		UserGroups: []string{"group1", "group2"},
		Domain:     "custom.example.com",
		NamePrefix: "my-prefix",
		AccessRestrictions: &daemonProto.ExposeAccessRestrictions{
			AllowedCidrs:     []string{"35.231.147.226/32"},
			BlockedCidrs:     []string{"198.51.100.0/24"},
			AllowedCountries: []string{"US"},
			BlockedCountries: []string{"RU"},
		},
	}

	exposeReq := NewRequest(req)

	assert.Equal(t, uint16(8080), exposeReq.Port, "port should match")
	assert.Equal(t, ProtocolType(daemonProto.ExposeProtocol_EXPOSE_HTTPS), exposeReq.Protocol, "protocol should match")
	assert.Equal(t, "123456", exposeReq.Pin, "pin should match")
	assert.Equal(t, "secret", exposeReq.Password, "password should match")
	assert.Equal(t, []string{"group1", "group2"}, exposeReq.UserGroups, "user groups should match")
	assert.Equal(t, "custom.example.com", exposeReq.Domain, "domain should match")
	assert.Equal(t, "my-prefix", exposeReq.NamePrefix, "name prefix should match")
	require.NotNil(t, exposeReq.AccessRestrictions)
	assert.Equal(t, []string{"35.231.147.226/32"}, exposeReq.AccessRestrictions.AllowedCIDRs)
	assert.Equal(t, []string{"198.51.100.0/24"}, exposeReq.AccessRestrictions.BlockedCIDRs)
	assert.Equal(t, []string{"US"}, exposeReq.AccessRestrictions.AllowedCountries)
	assert.Equal(t, []string{"RU"}, exposeReq.AccessRestrictions.BlockedCountries)
}
