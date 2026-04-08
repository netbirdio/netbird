package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
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
	assert.ErrorContains(t, rp.Validate(), "at least one target is required")
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

func TestValidateTargetOptions_PathRewrite(t *testing.T) {
	tests := []struct {
		name    string
		mode    PathRewriteMode
		wantErr string
	}{
		{"empty is default", "", ""},
		{"preserve is valid", PathRewritePreserve, ""},
		{"unknown rejected", "regex", "unknown path_rewrite mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := validProxy()
			rp.Targets[0].Options.PathRewrite = tt.mode
			err := rp.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTargetOptions_RequestTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		wantErr string
	}{
		{"valid 30s", 30 * time.Second, ""},
		{"valid 2m", 2 * time.Minute, ""},
		{"valid 10m", 10 * time.Minute, ""},
		{"zero is fine", 0, ""},
		{"negative", -1 * time.Second, "must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := validProxy()
			rp.Targets[0].Options.RequestTimeout = tt.timeout
			err := rp.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTargetOptions_CustomHeaders(t *testing.T) {
	t.Run("valid headers", func(t *testing.T) {
		rp := validProxy()
		rp.Targets[0].Options.CustomHeaders = map[string]string{
			"X-Custom": "value",
			"X-Trace":  "abc123",
		}
		assert.NoError(t, rp.Validate())
	})

	t.Run("CRLF in key", func(t *testing.T) {
		rp := validProxy()
		rp.Targets[0].Options.CustomHeaders = map[string]string{"X-Bad\r\nKey": "value"}
		assert.ErrorContains(t, rp.Validate(), "not a valid HTTP header name")
	})

	t.Run("CRLF in value", func(t *testing.T) {
		rp := validProxy()
		rp.Targets[0].Options.CustomHeaders = map[string]string{"X-Good": "bad\nvalue"}
		assert.ErrorContains(t, rp.Validate(), "invalid characters")
	})

	t.Run("hop-by-hop header rejected", func(t *testing.T) {
		for _, h := range []string{"Connection", "Transfer-Encoding", "Keep-Alive", "Upgrade", "Proxy-Connection"} {
			rp := validProxy()
			rp.Targets[0].Options.CustomHeaders = map[string]string{h: "value"}
			assert.ErrorContains(t, rp.Validate(), "hop-by-hop", "header %q should be rejected", h)
		}
	})

	t.Run("reserved header rejected", func(t *testing.T) {
		for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "Cookie", "Forwarded", "Content-Length", "Content-Type"} {
			rp := validProxy()
			rp.Targets[0].Options.CustomHeaders = map[string]string{h: "value"}
			assert.ErrorContains(t, rp.Validate(), "managed by the proxy", "header %q should be rejected", h)
		}
	})

	t.Run("Host header rejected", func(t *testing.T) {
		rp := validProxy()
		rp.Targets[0].Options.CustomHeaders = map[string]string{"Host": "evil.com"}
		assert.ErrorContains(t, rp.Validate(), "pass_host_header")
	})

	t.Run("too many headers", func(t *testing.T) {
		rp := validProxy()
		headers := make(map[string]string, 17)
		for i := range 17 {
			headers[fmt.Sprintf("X-H%d", i)] = "v"
		}
		rp.Targets[0].Options.CustomHeaders = headers
		assert.ErrorContains(t, rp.Validate(), "exceeds maximum of 16")
	})

	t.Run("key too long", func(t *testing.T) {
		rp := validProxy()
		rp.Targets[0].Options.CustomHeaders = map[string]string{strings.Repeat("X", 129): "v"}
		assert.ErrorContains(t, rp.Validate(), "key")
		assert.ErrorContains(t, rp.Validate(), "exceeds maximum length")
	})

	t.Run("value too long", func(t *testing.T) {
		rp := validProxy()
		rp.Targets[0].Options.CustomHeaders = map[string]string{"X-Ok": strings.Repeat("v", 4097)}
		assert.ErrorContains(t, rp.Validate(), "value exceeds maximum length")
	})

	t.Run("duplicate canonical keys rejected", func(t *testing.T) {
		rp := validProxy()
		rp.Targets[0].Options.CustomHeaders = map[string]string{
			"x-custom": "a",
			"X-Custom": "b",
		}
		assert.ErrorContains(t, rp.Validate(), "collide")
	})
}

func TestToProtoMapping_TargetOptions(t *testing.T) {
	rp := &Service{
		ID:        "svc-1",
		AccountID: "acc-1",
		Domain:    "example.com",
		Targets: []*Target{
			{
				TargetId:   "peer-1",
				TargetType: TargetTypePeer,
				Host:       "10.0.0.1",
				Port:       8080,
				Protocol:   "http",
				Enabled:    true,
				Options: TargetOptions{
					SkipTLSVerify:  true,
					RequestTimeout: 30 * time.Second,
					PathRewrite:    PathRewritePreserve,
					CustomHeaders:  map[string]string{"X-Custom": "val"},
				},
			},
		},
	}
	pm := rp.ToProtoMapping(Create, "token", proxy.OIDCValidationConfig{})
	require.Len(t, pm.Path, 1)

	opts := pm.Path[0].Options
	require.NotNil(t, opts, "options should be populated")
	assert.True(t, opts.SkipTlsVerify)
	assert.Equal(t, proto.PathRewriteMode_PATH_REWRITE_PRESERVE, opts.PathRewrite)
	assert.Equal(t, map[string]string{"X-Custom": "val"}, opts.CustomHeaders)
	require.NotNil(t, opts.RequestTimeout)
	assert.Equal(t, int64(30), opts.RequestTimeout.Seconds)
}

func TestToProtoMapping_NoOptionsWhenDefault(t *testing.T) {
	rp := &Service{
		ID:        "svc-1",
		AccountID: "acc-1",
		Domain:    "example.com",
		Targets: []*Target{
			{
				TargetId:   "peer-1",
				TargetType: TargetTypePeer,
				Host:       "10.0.0.1",
				Port:       8080,
				Protocol:   "http",
				Enabled:    true,
			},
		},
	}
	pm := rp.ToProtoMapping(Create, "token", proxy.OIDCValidationConfig{})
	require.Len(t, pm.Path, 1)
	assert.Nil(t, pm.Path[0].Options, "options should be nil when all defaults")
}

func TestIsDefaultPort(t *testing.T) {
	tests := []struct {
		scheme string
		port   uint16
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
	oidcConfig := proxy.OIDCValidationConfig{}

	tests := []struct {
		name       string
		protocol   string
		host       string
		port       uint16
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
	pm := rp.ToProtoMapping(Create, "token", proxy.OIDCValidationConfig{})
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
			pm := rp.ToProtoMapping(tt.op, "", proxy.OIDCValidationConfig{})
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

func TestGenerateExposeName(t *testing.T) {
	t.Run("no prefix generates 12-char name", func(t *testing.T) {
		name, err := GenerateExposeName("")
		require.NoError(t, err)
		assert.Len(t, name, 12)
		assert.Regexp(t, `^[a-z0-9]+$`, name)
	})

	t.Run("with prefix generates prefix-XXXX", func(t *testing.T) {
		name, err := GenerateExposeName("myapp")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(name, "myapp-"), "name should start with prefix")
		suffix := strings.TrimPrefix(name, "myapp-")
		assert.Len(t, suffix, 4, "suffix should be 4 chars")
		assert.Regexp(t, `^[a-z0-9]+$`, suffix)
	})

	t.Run("unique names", func(t *testing.T) {
		names := make(map[string]bool)
		for i := 0; i < 50; i++ {
			name, err := GenerateExposeName("")
			require.NoError(t, err)
			names[name] = true
		}
		assert.Greater(t, len(names), 45, "should generate mostly unique names")
	})

	t.Run("valid prefixes", func(t *testing.T) {
		validPrefixes := []string{"a", "ab", "a1", "my-app", "web-server-01", "a-b"}
		for _, prefix := range validPrefixes {
			name, err := GenerateExposeName(prefix)
			assert.NoError(t, err, "prefix %q should be valid", prefix)
			assert.True(t, strings.HasPrefix(name, prefix+"-"), "name should start with %q-", prefix)
		}
	})

	t.Run("invalid prefixes", func(t *testing.T) {
		invalidPrefixes := []string{
			"-starts-with-dash",
			"ends-with-dash-",
			"has.dots",
			"HAS-UPPER",
			"has spaces",
			"has/slash",
			"a--",
		}
		for _, prefix := range invalidPrefixes {
			_, err := GenerateExposeName(prefix)
			assert.Error(t, err, "prefix %q should be invalid", prefix)
			assert.Contains(t, err.Error(), "invalid name prefix")
		}
	})
}

func TestExposeServiceRequest_ToService(t *testing.T) {
	t.Run("basic HTTP service", func(t *testing.T) {
		req := &ExposeServiceRequest{
			Port: 8080,
			Mode: "http",
		}

		service := req.ToService("account-1", "peer-1", "mysvc")

		assert.Equal(t, "account-1", service.AccountID)
		assert.Equal(t, "mysvc", service.Name)
		assert.True(t, service.Enabled)
		assert.Empty(t, service.Domain, "domain should be empty when not specified")
		require.Len(t, service.Targets, 1)

		target := service.Targets[0]
		assert.Equal(t, uint16(8080), target.Port)
		assert.Equal(t, "http", target.Protocol)
		assert.Equal(t, "peer-1", target.TargetId)
		assert.Equal(t, TargetTypePeer, target.TargetType)
		assert.True(t, target.Enabled)
		assert.Equal(t, "account-1", target.AccountID)
	})

	t.Run("with custom domain", func(t *testing.T) {
		req := &ExposeServiceRequest{
			Port:   3000,
			Domain: "example.com",
		}

		service := req.ToService("acc", "peer", "web")
		assert.Equal(t, "web.example.com", service.Domain)
	})

	t.Run("with PIN auth", func(t *testing.T) {
		req := &ExposeServiceRequest{
			Port: 80,
			Pin:  "1234",
		}

		service := req.ToService("acc", "peer", "svc")
		require.NotNil(t, service.Auth.PinAuth)
		assert.True(t, service.Auth.PinAuth.Enabled)
		assert.Equal(t, "1234", service.Auth.PinAuth.Pin)
		assert.Nil(t, service.Auth.PasswordAuth)
		assert.Nil(t, service.Auth.BearerAuth)
	})

	t.Run("with password auth", func(t *testing.T) {
		req := &ExposeServiceRequest{
			Port:     80,
			Password: "secret",
		}

		service := req.ToService("acc", "peer", "svc")
		require.NotNil(t, service.Auth.PasswordAuth)
		assert.True(t, service.Auth.PasswordAuth.Enabled)
		assert.Equal(t, "secret", service.Auth.PasswordAuth.Password)
	})

	t.Run("with user groups (bearer auth)", func(t *testing.T) {
		req := &ExposeServiceRequest{
			Port:       80,
			UserGroups: []string{"admins", "devs"},
		}

		service := req.ToService("acc", "peer", "svc")
		require.NotNil(t, service.Auth.BearerAuth)
		assert.True(t, service.Auth.BearerAuth.Enabled)
		assert.Equal(t, []string{"admins", "devs"}, service.Auth.BearerAuth.DistributionGroups)
	})

	t.Run("with all auth types", func(t *testing.T) {
		req := &ExposeServiceRequest{
			Port:       443,
			Domain:     "myco.com",
			Pin:        "9999",
			Password:   "pass",
			UserGroups: []string{"ops"},
		}

		service := req.ToService("acc", "peer", "full")
		assert.Equal(t, "full.myco.com", service.Domain)
		require.NotNil(t, service.Auth.PinAuth)
		require.NotNil(t, service.Auth.PasswordAuth)
		require.NotNil(t, service.Auth.BearerAuth)
	})
}

func TestValidate_TLSOnly(t *testing.T) {
	rp := &Service{
		Name:       "tls-svc",
		Mode:       "tls",
		Domain:     "example.com",
		ListenPort: 8443,
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "tcp", Port: 443, Enabled: true},
		},
	}
	require.NoError(t, rp.Validate())
}

func TestValidate_TLSMissingListenPort(t *testing.T) {
	rp := &Service{
		Name:       "tls-svc",
		Mode:       "tls",
		Domain:     "example.com",
		ListenPort: 0,
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "tcp", Port: 443, Enabled: true},
		},
	}
	assert.ErrorContains(t, rp.Validate(), "listen_port is required")
}

func TestValidate_TLSMissingDomain(t *testing.T) {
	rp := &Service{
		Name:       "tls-svc",
		Mode:       "tls",
		ListenPort: 8443,
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "tcp", Port: 443, Enabled: true},
		},
	}
	assert.ErrorContains(t, rp.Validate(), "domain is required")
}

func TestValidate_TCPValid(t *testing.T) {
	rp := &Service{
		Name:       "tcp-svc",
		Mode:       "tcp",
		Domain:     "cluster.test",
		ListenPort: 5432,
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "tcp", Port: 5432, Enabled: true},
		},
	}
	require.NoError(t, rp.Validate())
}

func TestValidate_TCPMissingListenPort(t *testing.T) {
	rp := &Service{
		Name:   "tcp-svc",
		Mode:   "tcp",
		Domain: "cluster.test",
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "tcp", Port: 5432, Enabled: true},
		},
	}
	require.NoError(t, rp.Validate(), "TCP with listen_port=0 is valid (auto-assigned by manager)")
}

func TestValidate_L4MultipleTargets(t *testing.T) {
	rp := &Service{
		Name:       "tcp-svc",
		Mode:       "tcp",
		Domain:     "cluster.test",
		ListenPort: 5432,
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "tcp", Port: 5432, Enabled: true},
			{TargetId: "peer-2", TargetType: TargetTypePeer, Protocol: "tcp", Port: 5432, Enabled: true},
		},
	}
	assert.ErrorContains(t, rp.Validate(), "exactly one target")
}

func TestValidate_L4TargetMissingPort(t *testing.T) {
	rp := &Service{
		Name:       "tcp-svc",
		Mode:       "tcp",
		Domain:     "cluster.test",
		ListenPort: 5432,
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "tcp", Port: 0, Enabled: true},
		},
	}
	assert.ErrorContains(t, rp.Validate(), "port is required")
}

func TestValidate_TLSInvalidTargetType(t *testing.T) {
	rp := &Service{
		Name:       "tls-svc",
		Mode:       "tls",
		Domain:     "example.com",
		ListenPort: 443,
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: "invalid", Protocol: "tcp", Port: 443, Enabled: true},
		},
	}
	assert.Error(t, rp.Validate())
}

func TestValidate_TLSSubnetValid(t *testing.T) {
	rp := &Service{
		Name:       "tls-subnet",
		Mode:       "tls",
		Domain:     "example.com",
		ListenPort: 8443,
		Targets: []*Target{
			{TargetId: "subnet-1", TargetType: TargetTypeSubnet, Protocol: "tcp", Port: 443, Host: "10.0.0.5", Enabled: true},
		},
	}
	require.NoError(t, rp.Validate())
}

func TestValidate_L4DomainTargetValid(t *testing.T) {
	modes := []struct {
		mode  string
		port  uint16
		proto string
	}{
		{"tcp", 5432, "tcp"},
		{"tls", 443, "tcp"},
		{"udp", 5432, "udp"},
	}
	for _, m := range modes {
		t.Run(m.mode, func(t *testing.T) {
			rp := &Service{
				Name:       m.mode + "-domain",
				Mode:       m.mode,
				Domain:     "cluster.test",
				ListenPort: m.port,
				Targets: []*Target{
					{TargetId: "resource-1", TargetType: TargetTypeDomain, Protocol: m.proto, Port: m.port, Enabled: true},
				},
			}
			require.NoError(t, rp.Validate())
		})
	}
}

func TestValidate_HTTPProxyProtocolRejected(t *testing.T) {
	rp := validProxy()
	rp.Targets[0].ProxyProtocol = true
	assert.ErrorContains(t, rp.Validate(), "proxy_protocol is not supported for HTTP")
}

func TestValidate_UDPProxyProtocolRejected(t *testing.T) {
	rp := &Service{
		Name:   "udp-svc",
		Mode:   "udp",
		Domain: "cluster.test",
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "udp", Port: 5432, Enabled: true, ProxyProtocol: true},
		},
	}
	assert.ErrorContains(t, rp.Validate(), "proxy_protocol is not supported for UDP")
}

func TestValidate_TCPProxyProtocolAllowed(t *testing.T) {
	rp := &Service{
		Name:       "tcp-svc",
		Mode:       "tcp",
		Domain:     "cluster.test",
		ListenPort: 5432,
		Targets: []*Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Protocol: "tcp", Port: 5432, Enabled: true, ProxyProtocol: true},
		},
	}
	require.NoError(t, rp.Validate())
}

func TestExposeServiceRequest_Validate_L4RejectsAuth(t *testing.T) {
	tests := []struct {
		name string
		req  ExposeServiceRequest
	}{
		{
			name: "tcp with pin",
			req:  ExposeServiceRequest{Port: 8080, Mode: "tcp", Pin: "123456"},
		},
		{
			name: "udp with password",
			req:  ExposeServiceRequest{Port: 8080, Mode: "udp", Password: "secret"},
		},
		{
			name: "tls with user groups",
			req:  ExposeServiceRequest{Port: 443, Mode: "tls", UserGroups: []string{"admins"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "authentication is not supported")
		})
	}
}

func TestExposeServiceRequest_Validate_HTTPAllowsAuth(t *testing.T) {
	req := ExposeServiceRequest{Port: 8080, Mode: "http", Pin: "123456"}
	require.NoError(t, req.Validate())
}

func TestValidate_HeaderAuths(t *testing.T) {
	t.Run("single valid header", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: true, Header: "X-API-Key", Value: "secret"},
			},
		}
		require.NoError(t, rp.Validate())
	})

	t.Run("multiple headers same canonical name allowed", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: true, Header: "Authorization", Value: "Bearer token-1"},
				{Enabled: true, Header: "Authorization", Value: "Bearer token-2"},
			},
		}
		require.NoError(t, rp.Validate())
	})

	t.Run("multiple headers different case same canonical allowed", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: true, Header: "x-api-key", Value: "key-1"},
				{Enabled: true, Header: "X-Api-Key", Value: "key-2"},
			},
		}
		require.NoError(t, rp.Validate())
	})

	t.Run("multiple different headers allowed", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: true, Header: "Authorization", Value: "Bearer tok"},
				{Enabled: true, Header: "X-API-Key", Value: "key"},
			},
		}
		require.NoError(t, rp.Validate())
	})

	t.Run("empty header name rejected", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: true, Header: "", Value: "val"},
			},
		}
		err := rp.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "header name is required")
	})

	t.Run("hop-by-hop header rejected", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: true, Header: "Connection", Value: "val"},
			},
		}
		err := rp.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hop-by-hop")
	})

	t.Run("host header rejected", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: true, Header: "Host", Value: "val"},
			},
		}
		err := rp.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Host header cannot be used")
	})

	t.Run("disabled entries skipped", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: false, Header: "", Value: ""},
				{Enabled: true, Header: "X-Key", Value: "val"},
			},
		}
		require.NoError(t, rp.Validate())
	})

	t.Run("value too long rejected", func(t *testing.T) {
		rp := validProxy()
		rp.Auth = AuthConfig{
			HeaderAuths: []*HeaderAuthConfig{
				{Enabled: true, Header: "X-Key", Value: strings.Repeat("a", maxHeaderValueLen+1)},
			},
		}
		err := rp.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum length")
	})
}
