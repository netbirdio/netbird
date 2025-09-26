package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/ssh/client"
	"github.com/netbirdio/netbird/client/ssh/detection"
	"github.com/netbirdio/netbird/client/ssh/testutil"
	nbjwt "github.com/netbirdio/netbird/management/server/auth/jwt"
)

func TestJWTEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping JWT enforcement tests in short mode")
	}

	// Set up SSH server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	t.Run("blocks_without_jwt", func(t *testing.T) {
		jwtConfig := &JWTConfig{
			Issuer:       "test-issuer",
			Audience:     "test-audience",
			KeysLocation: "test-keys",
		}
		server := New(hostKey, jwtConfig)
		server.SetAllowRootLogin(true)

		serverAddr := StartTestServer(t, server)
		defer require.NoError(t, server.Stop())

		host, portStr, err := net.SplitHostPort(serverAddr)
		require.NoError(t, err)
		port, err := strconv.Atoi(portStr)
		require.NoError(t, err)
		serverType, err := detection.DetectSSHServerType(context.Background(), host, port)
		if err != nil {
			t.Logf("Detection failed: %v", err)
		}
		t.Logf("Detected server type: %s", serverType)

		config := &cryptossh.ClientConfig{
			User:            testutil.GetTestUsername(t),
			Auth:            []cryptossh.AuthMethod{},
			HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		}

		_, err = cryptossh.Dial("tcp", net.JoinHostPort(host, portStr), config)
		assert.Error(t, err, "SSH connection should fail when JWT is required but not provided")
	})

	t.Run("allows_when_disabled", func(t *testing.T) {
		serverNoJWT := New(hostKey, nil)
		require.False(t, serverNoJWT.jwtEnabled, "JWT should be disabled without config")
		serverNoJWT.SetAllowRootLogin(true)

		serverAddrNoJWT := StartTestServer(t, serverNoJWT)
		defer require.NoError(t, serverNoJWT.Stop())

		hostNoJWT, portStrNoJWT, err := net.SplitHostPort(serverAddrNoJWT)
		require.NoError(t, err)
		portNoJWT, err := strconv.Atoi(portStrNoJWT)
		require.NoError(t, err)

		serverType, err := detection.DetectSSHServerType(context.Background(), hostNoJWT, portNoJWT)
		require.NoError(t, err)
		assert.Equal(t, detection.ServerTypeNetBirdNoJWT, serverType)
		assert.False(t, serverType.RequiresJWT())

		client, err := connectWithNetBirdClient(t, hostNoJWT, portNoJWT)
		require.NoError(t, err)
		defer client.Close()
	})

}

// setupJWKSServer creates a test HTTP server serving JWKS and returns the server, private key, and URL
func setupJWKSServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey, string) {
	privateKey, jwksJSON := generateTestJWKS(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(jwksJSON); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))

	return server, privateKey, server.URL
}

// generateTestJWKS creates a test RSA key pair and returns private key and JWKS JSON
func generateTestJWKS(t *testing.T) (*rsa.PrivateKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey
	n := publicKey.N.Bytes()
	e := publicKey.E

	jwk := nbjwt.JSONWebKey{
		Kty: "RSA",
		Kid: "test-key-id",
		Use: "sig",
		N:   base64RawURLEncode(n),
		E:   base64RawURLEncode(big.NewInt(int64(e)).Bytes()),
	}

	jwks := nbjwt.Jwks{
		Keys: []nbjwt.JSONWebKey{jwk},
	}

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	return privateKey, jwksJSON
}

func base64RawURLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// generateValidJWT creates a valid JWT token for testing
func generateValidJWT(t *testing.T, privateKey *rsa.PrivateKey, issuer, audience string) string {
	claims := jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-id"

	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return tokenString
}

// connectWithNetBirdClient connects to SSH server using NetBird's SSH client
func connectWithNetBirdClient(t *testing.T, host string, port int) (*client.Client, error) {
	t.Helper()
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	ctx := context.Background()
	return client.Dial(ctx, addr, testutil.GetTestUsername(t), client.DialOptions{
		InsecureSkipVerify: true,
	})
}

// TestJWTDetection tests that server detection correctly identifies JWT-enabled servers
func TestJWTDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping JWT detection test in short mode")
	}

	jwksServer, _, jwksURL := setupJWKSServer(t)
	defer jwksServer.Close()

	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	const (
		issuer   = "https://test-issuer.example.com"
		audience = "test-audience"
	)

	jwtConfig := &JWTConfig{
		Issuer:       issuer,
		Audience:     audience,
		KeysLocation: jwksURL,
	}
	server := New(hostKey, jwtConfig)
	server.SetAllowRootLogin(true)

	serverAddr := StartTestServer(t, server)
	defer require.NoError(t, server.Stop())

	host, portStr, err := net.SplitHostPort(serverAddr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	serverType, err := detection.DetectSSHServerType(context.Background(), host, port)
	require.NoError(t, err)
	assert.Equal(t, detection.ServerTypeNetBirdJWT, serverType)
	assert.True(t, serverType.RequiresJWT())
}

// TestJWTAuthentication tests JWT authentication with valid/invalid tokens and enforcement for various connection types
func TestJWTAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping JWT authentication tests in short mode")
	}

	jwksServer, privateKey, jwksURL := setupJWKSServer(t)
	defer jwksServer.Close()

	const (
		issuer   = "https://test-issuer.example.com"
		audience = "test-audience"
	)

	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		token         string
		wantAuthOK    bool
		setupServer   func(*Server)
		testOperation func(*testing.T, *cryptossh.Client, string) error
		wantOpSuccess bool
	}{
		{
			name:       "allows_shell_with_jwt",
			token:      "valid",
			wantAuthOK: true,
			setupServer: func(s *Server) {
				s.SetAllowRootLogin(true)
			},
			testOperation: func(t *testing.T, conn *cryptossh.Client, _ string) error {
				session, err := conn.NewSession()
				require.NoError(t, err)
				defer session.Close()
				return session.Shell()
			},
			wantOpSuccess: true,
		},
		{
			name:       "rejects_invalid_token",
			token:      "invalid",
			wantAuthOK: false,
			setupServer: func(s *Server) {
				s.SetAllowRootLogin(true)
			},
			testOperation: func(t *testing.T, conn *cryptossh.Client, _ string) error {
				session, err := conn.NewSession()
				require.NoError(t, err)
				defer session.Close()

				output, err := session.CombinedOutput("echo test")
				if err != nil {
					t.Logf("Command output: %s", string(output))
					return err
				}
				return nil
			},
			wantOpSuccess: false,
		},
		{
			name:       "blocks_shell_without_jwt",
			token:      "",
			wantAuthOK: false,
			setupServer: func(s *Server) {
				s.SetAllowRootLogin(true)
			},
			testOperation: func(t *testing.T, conn *cryptossh.Client, _ string) error {
				session, err := conn.NewSession()
				require.NoError(t, err)
				defer session.Close()

				output, err := session.CombinedOutput("echo test")
				if err != nil {
					t.Logf("Command output: %s", string(output))
					return err
				}
				return nil
			},
			wantOpSuccess: false,
		},
		{
			name:       "blocks_command_without_jwt",
			token:      "",
			wantAuthOK: false,
			setupServer: func(s *Server) {
				s.SetAllowRootLogin(true)
			},
			testOperation: func(t *testing.T, conn *cryptossh.Client, _ string) error {
				session, err := conn.NewSession()
				require.NoError(t, err)
				defer session.Close()

				output, err := session.CombinedOutput("ls")
				if err != nil {
					t.Logf("Command output: %s", string(output))
					return err
				}
				return nil
			},
			wantOpSuccess: false,
		},
		{
			name:       "allows_sftp_with_jwt",
			token:      "valid",
			wantAuthOK: true,
			setupServer: func(s *Server) {
				s.SetAllowRootLogin(true)
				s.SetAllowSFTP(true)
			},
			testOperation: func(t *testing.T, conn *cryptossh.Client, _ string) error {
				session, err := conn.NewSession()
				require.NoError(t, err)
				defer session.Close()

				session.Stdout = io.Discard
				session.Stderr = io.Discard
				return session.RequestSubsystem("sftp")
			},
			wantOpSuccess: true,
		},
		{
			name:       "blocks_sftp_without_jwt",
			token:      "",
			wantAuthOK: false,
			setupServer: func(s *Server) {
				s.SetAllowRootLogin(true)
				s.SetAllowSFTP(true)
			},
			testOperation: func(t *testing.T, conn *cryptossh.Client, _ string) error {
				session, err := conn.NewSession()
				require.NoError(t, err)
				defer session.Close()

				session.Stdout = io.Discard
				session.Stderr = io.Discard
				err = session.RequestSubsystem("sftp")
				if err == nil {
					err = session.Wait()
				}
				return err
			},
			wantOpSuccess: false,
		},
		{
			name:       "allows_port_forward_with_jwt",
			token:      "valid",
			wantAuthOK: true,
			setupServer: func(s *Server) {
				s.SetAllowRootLogin(true)
				s.SetAllowRemotePortForwarding(true)
			},
			testOperation: func(t *testing.T, conn *cryptossh.Client, _ string) error {
				ln, err := conn.Listen("tcp", "127.0.0.1:0")
				if ln != nil {
					defer ln.Close()
				}
				return err
			},
			wantOpSuccess: true,
		},
		{
			name:       "blocks_port_forward_without_jwt",
			token:      "",
			wantAuthOK: false,
			setupServer: func(s *Server) {
				s.SetAllowRootLogin(true)
				s.SetAllowLocalPortForwarding(true)
			},
			testOperation: func(t *testing.T, conn *cryptossh.Client, _ string) error {
				ln, err := conn.Listen("tcp", "127.0.0.1:0")
				if ln != nil {
					defer ln.Close()
				}
				return err
			},
			wantOpSuccess: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwtConfig := &JWTConfig{
				Issuer:       issuer,
				Audience:     audience,
				KeysLocation: jwksURL,
			}
			server := New(hostKey, jwtConfig)
			if tc.setupServer != nil {
				tc.setupServer(server)
			}

			serverAddr := StartTestServer(t, server)
			defer require.NoError(t, server.Stop())

			host, portStr, err := net.SplitHostPort(serverAddr)
			require.NoError(t, err)

			var authMethods []cryptossh.AuthMethod
			if tc.token == "valid" {
				token := generateValidJWT(t, privateKey, issuer, audience)
				authMethods = []cryptossh.AuthMethod{
					cryptossh.Password(token),
				}
			} else if tc.token == "invalid" {
				invalidToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid"
				authMethods = []cryptossh.AuthMethod{
					cryptossh.Password(invalidToken),
				}
			}

			config := &cryptossh.ClientConfig{
				User:            testutil.GetTestUsername(t),
				Auth:            authMethods,
				HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			}

			conn, err := cryptossh.Dial("tcp", net.JoinHostPort(host, portStr), config)
			if tc.wantAuthOK {
				require.NoError(t, err, "JWT authentication should succeed")
			} else {
				if err != nil {
					t.Logf("Connection failed as expected: %v", err)
					return
				}
			}
			if conn != nil {
				defer func() {
					if err := conn.Close(); err != nil {
						t.Logf("close connection: %v", err)
					}
				}()
			}

			err = tc.testOperation(t, conn, serverAddr)
			if tc.wantOpSuccess {
				require.NoError(t, err, "Operation should succeed")
			} else {
				assert.Error(t, err, "Operation should fail")
			}
		})
	}
}
