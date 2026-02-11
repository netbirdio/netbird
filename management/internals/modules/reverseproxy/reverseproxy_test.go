package reverseproxy

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/hash/argon2id"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func validProxy() *Service {
	return &Service{
		Name:   "test",
		Domain: "example.com",
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Host: "10.0.0.1", Port: 80, Protocol: "http", Enabled: true},
		},
	}
}

func TestValidate_Valid(t *testing.T) {
	require.NoError(t, validProxy().Validate())
}

func TestValidate_EmptyName(t *testing.T) {
	rp := validProxy()
	rp.Name = ""
	assert.ErrorContains(t, rp.Validate(), "name is required")
}

func TestValidate_EmptyDomain(t *testing.T) {
	rp := validProxy()
	rp.Domain = ""
	assert.ErrorContains(t, rp.Validate(), "domain is required")
}

func TestValidate_NoTargets(t *testing.T) {
	rp := validProxy()
	rp.Targets = nil
	assert.ErrorContains(t, rp.Validate(), "at least one target")
}

func TestValidate_EmptyTargetId(t *testing.T) {
	rp := validProxy()
	rp.Targets[0].TargetId = ""
	assert.ErrorContains(t, rp.Validate(), "empty target_id")
}

func TestValidate_InvalidTargetType(t *testing.T) {
	rp := validProxy()
	rp.Targets[0].TargetType = "invalid"
	assert.ErrorContains(t, rp.Validate(), "invalid target_type")
}

func TestValidate_ResourceTarget(t *testing.T) {
	rp := validProxy()
	rp.Targets = append(rp.Targets, &Target{
		TargetId:   "resource-1",
		TargetType: TargetTypeHost,
		Host:       "example.org",
		Port:       443,
		Protocol:   "https",
		Enabled:    true,
	})
	require.NoError(t, rp.Validate())
}

func TestValidate_MultipleTargetsOneInvalid(t *testing.T) {
	rp := validProxy()
	rp.Targets = append(rp.Targets, &Target{
		TargetId:   "",
		TargetType: TargetTypePeer,
		Host:       "10.0.0.2",
		Port:       80,
		Protocol:   "http",
		Enabled:    true,
	})
	err := rp.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target 1")
	assert.Contains(t, err.Error(), "empty target_id")
}

func TestIsDefaultPort(t *testing.T) {
	tests := []struct {
		scheme string
		port   int
		want   bool
	}{
		{"http", 80, true},
		{"https", 443, true},
		{"http", 443, false},
		{"https", 80, false},
		{"http", 8080, false},
		{"https", 8443, false},
		{"http", 0, false},
		{"https", 0, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%d", tt.scheme, tt.port), func(t *testing.T) {
			assert.Equal(t, tt.want, isDefaultPort(tt.scheme, tt.port))
		})
	}
}

func TestToProtoMapping_PortInTargetURL(t *testing.T) {
	oidcConfig := OIDCValidationConfig{}

	tests := []struct {
		name       string
		protocol   string
		host       string
		port       int
		wantTarget string
	}{
		{
			name:       "http with default port 80 omits port",
			protocol:   "http",
			host:       "10.0.0.1",
			port:       80,
			wantTarget: "http://10.0.0.1/",
		},
		{
			name:       "https with default port 443 omits port",
			protocol:   "https",
			host:       "10.0.0.1",
			port:       443,
			wantTarget: "https://10.0.0.1/",
		},
		{
			name:       "port 0 omits port",
			protocol:   "http",
			host:       "10.0.0.1",
			port:       0,
			wantTarget: "http://10.0.0.1/",
		},
		{
			name:       "non-default port is included",
			protocol:   "http",
			host:       "10.0.0.1",
			port:       8080,
			wantTarget: "http://10.0.0.1:8080/",
		},
		{
			name:       "https with non-default port is included",
			protocol:   "https",
			host:       "10.0.0.1",
			port:       8443,
			wantTarget: "https://10.0.0.1:8443/",
		},
		{
			name:       "http port 443 is included",
			protocol:   "http",
			host:       "10.0.0.1",
			port:       443,
			wantTarget: "http://10.0.0.1:443/",
		},
		{
			name:       "https port 80 is included",
			protocol:   "https",
			host:       "10.0.0.1",
			port:       80,
			wantTarget: "https://10.0.0.1:80/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := &Service{
				ID:        "test-id",
				AccountID: "acc-1",
				Domain:    "example.com",
				Targets: []*Target{
					{
						TargetId:   "peer-1",
						TargetType: TargetTypePeer,
						Host:       tt.host,
						Port:       tt.port,
						Protocol:   tt.protocol,
						Enabled:    true,
					},
				},
			}
			pm := rp.ToProtoMapping(Create, "token", oidcConfig)
			require.Len(t, pm.Path, 1, "should have one path mapping")
			assert.Equal(t, tt.wantTarget, pm.Path[0].Target)
		})
	}
}

func TestToProtoMapping_DisabledTargetSkipped(t *testing.T) {
	rp := &Service{
		ID:        "test-id",
		AccountID: "acc-1",
		Domain:    "example.com",
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Host: "10.0.0.1", Port: 8080, Protocol: "http", Enabled: false},
			{TargetId: "peer-2", TargetType: TargetTypePeer, Host: "10.0.0.2", Port: 9090, Protocol: "http", Enabled: true},
		},
	}
	pm := rp.ToProtoMapping(Create, "token", OIDCValidationConfig{})
	require.Len(t, pm.Path, 1)
	assert.Equal(t, "http://10.0.0.2:9090/", pm.Path[0].Target)
}

func TestToProtoMapping_OperationTypes(t *testing.T) {
	rp := validProxy()
	tests := []struct {
		op   Operation
		want proto.ProxyMappingUpdateType
	}{
		{Create, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED},
		{Update, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED},
		{Delete, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED},
	}
	for _, tt := range tests {
		t.Run(string(tt.op), func(t *testing.T) {
			pm := rp.ToProtoMapping(tt.op, "", OIDCValidationConfig{})
			assert.Equal(t, tt.want, pm.Type)
		})
	}
}

func TestAuthConfig_HashSecrets(t *testing.T) {
	tests := []struct {
		name     string
		config   *AuthConfig
		wantErr  bool
		validate func(*testing.T, *AuthConfig)
	}{
		{
			name: "hash password successfully",
			config: &AuthConfig{
				PasswordAuth: &PasswordAuthConfig{
					Enabled:  true,
					Password: "testPassword123",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, config *AuthConfig) {
				if !strings.HasPrefix(config.PasswordAuth.Password, "$argon2id$") {
					t.Errorf("Password not hashed with argon2id, got: %s", config.PasswordAuth.Password)
				}
				// Verify the hash can be verified
				if err := argon2id.Verify("testPassword123", config.PasswordAuth.Password); err != nil {
					t.Errorf("Hash verification failed: %v", err)
				}
			},
		},
		{
			name: "hash PIN successfully",
			config: &AuthConfig{
				PinAuth: &PINAuthConfig{
					Enabled: true,
					Pin:     "123456",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, config *AuthConfig) {
				if !strings.HasPrefix(config.PinAuth.Pin, "$argon2id$") {
					t.Errorf("PIN not hashed with argon2id, got: %s", config.PinAuth.Pin)
				}
				// Verify the hash can be verified
				if err := argon2id.Verify("123456", config.PinAuth.Pin); err != nil {
					t.Errorf("Hash verification failed: %v", err)
				}
			},
		},
		{
			name: "hash both password and PIN",
			config: &AuthConfig{
				PasswordAuth: &PasswordAuthConfig{
					Enabled:  true,
					Password: "password",
				},
				PinAuth: &PINAuthConfig{
					Enabled: true,
					Pin:     "9999",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, config *AuthConfig) {
				if !strings.HasPrefix(config.PasswordAuth.Password, "$argon2id$") {
					t.Errorf("Password not hashed with argon2id")
				}
				if !strings.HasPrefix(config.PinAuth.Pin, "$argon2id$") {
					t.Errorf("PIN not hashed with argon2id")
				}
				if err := argon2id.Verify("password", config.PasswordAuth.Password); err != nil {
					t.Errorf("Password hash verification failed: %v", err)
				}
				if err := argon2id.Verify("9999", config.PinAuth.Pin); err != nil {
					t.Errorf("PIN hash verification failed: %v", err)
				}
			},
		},
		{
			name: "skip disabled password auth",
			config: &AuthConfig{
				PasswordAuth: &PasswordAuthConfig{
					Enabled:  false,
					Password: "password",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, config *AuthConfig) {
				if config.PasswordAuth.Password != "password" {
					t.Errorf("Disabled password auth should not be hashed")
				}
			},
		},
		{
			name: "skip empty password",
			config: &AuthConfig{
				PasswordAuth: &PasswordAuthConfig{
					Enabled:  true,
					Password: "",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, config *AuthConfig) {
				if config.PasswordAuth.Password != "" {
					t.Errorf("Empty password should remain empty")
				}
			},
		},
		{
			name: "skip nil password auth",
			config: &AuthConfig{
				PasswordAuth: nil,
				PinAuth: &PINAuthConfig{
					Enabled: true,
					Pin:     "1234",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, config *AuthConfig) {
				if config.PasswordAuth != nil {
					t.Errorf("PasswordAuth should remain nil")
				}
				if !strings.HasPrefix(config.PinAuth.Pin, "$argon2id$") {
					t.Errorf("PIN should still be hashed")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.HashSecrets()
			if (err != nil) != tt.wantErr {
				t.Errorf("HashSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.validate != nil {
				tt.validate(t, tt.config)
			}
		})
	}
}

func TestAuthConfig_HashSecrets_VerifyIncorrectSecret(t *testing.T) {
	config := &AuthConfig{
		PasswordAuth: &PasswordAuthConfig{
			Enabled:  true,
			Password: "correctPassword",
		},
	}

	if err := config.HashSecrets(); err != nil {
		t.Fatalf("HashSecrets() error = %v", err)
	}

	// Verify with wrong password should fail
	err := argon2id.Verify("wrongPassword", config.PasswordAuth.Password)
	if !errors.Is(err, argon2id.ErrMismatchedHashAndPassword) {
		t.Errorf("Expected ErrMismatchedHashAndPassword, got %v", err)
	}
}

func TestAuthConfig_ClearSecrets(t *testing.T) {
	config := &AuthConfig{
		PasswordAuth: &PasswordAuthConfig{
			Enabled:  true,
			Password: "hashedPassword",
		},
		PinAuth: &PINAuthConfig{
			Enabled: true,
			Pin:     "hashedPin",
		},
	}

	config.ClearSecrets()

	if config.PasswordAuth.Password != "" {
		t.Errorf("Password not cleared, got: %s", config.PasswordAuth.Password)
	}
	if config.PinAuth.Pin != "" {
		t.Errorf("PIN not cleared, got: %s", config.PinAuth.Pin)
	}
}
