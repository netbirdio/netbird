package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os/user"
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
	nbjwt "github.com/netbirdio/netbird/management/server/auth/jwt"
)

func getCurrentUsername(t *testing.T) string {
	t.Helper()
	currentUser, err := user.Current()
	require.NoError(t, err)
	return currentUser.Username
}

func TestJWTEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping JWT enforcement tests in short mode")
	}

	// Set up SSH server
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	clientPubKey, err := nbssh.GeneratePublicKey(clientPrivKey)
	require.NoError(t, err)

	t.Run("blocks_without_jwt", func(t *testing.T) {
		jwtConfig := &JWTConfig{
			Issuer:       "test-issuer",
			Audience:     "test-audience",
			KeysLocation: "test-keys",
		}
		server := New(hostKey, jwtConfig)
		server.SetAllowRootLogin(true)
		err = server.AddAuthorizedKey("test-peer", string(clientPubKey))
		require.NoError(t, err)

		serverAddr := StartTestServer(t, server)
		defer require.NoError(t, server.Stop())

		host, portStr, err := net.SplitHostPort(serverAddr)
		require.NoError(t, err)
		port, err := strconv.Atoi(portStr)
		require.NoError(t, err)
		serverType, err := detection.DetectSSHServerType(context.Background(), host, port, "")
		if err != nil {
			t.Logf("Detection failed: %v", err)
		}
		t.Logf("Detected server type: %s", serverType)

		config := &cryptossh.ClientConfig{
			User:            getCurrentUsername(t),
			Auth:            []cryptossh.AuthMethod{},
			HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		}

		conn, err := cryptossh.Dial("tcp", net.JoinHostPort(host, portStr), config)
		require.NoError(t, err, "Connection should succeed")
		defer conn.Close()

		session, err := conn.NewSession()
		require.NoError(t, err, "Session creation should succeed")
		defer session.Close()

		output, err := session.CombinedOutput("echo test")
		assert.Error(t, err, "Should return error when JWT required")
		assert.Contains(t, string(output), "JWT authentication required")
	})

	t.Run("allows_when_disabled", func(t *testing.T) {
		serverNoJWT := New(hostKey, nil)
		require.False(t, serverNoJWT.jwtEnabled, "JWT should be disabled without config")
		serverNoJWT.SetAllowRootLogin(true)
		err := serverNoJWT.AddAuthorizedKey("test-peer", string(clientPubKey))
		require.NoError(t, err)

		serverAddrNoJWT := StartTestServer(t, serverNoJWT)
		defer require.NoError(t, serverNoJWT.Stop())

		hostNoJWT, portStrNoJWT, err := net.SplitHostPort(serverAddrNoJWT)
		require.NoError(t, err)
		portNoJWT, err := strconv.Atoi(portStrNoJWT)
		require.NoError(t, err)

		serverType, err := detection.DetectSSHServerType(context.Background(), hostNoJWT, portNoJWT, "")
		require.NoError(t, err)
		assert.Equal(t, detection.ServerTypeNetBirdNoJWT, serverType)
		assert.False(t, serverType.RequiresJWT())

		client, err := connectWithNetBirdClient(t, hostNoJWT, portNoJWT, clientPrivKey)
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

// sendJWTAuthRequest sends a JWT auth request over SSH connection
func sendJWTAuthRequest(conn *cryptossh.Client, token string) error {
	authReq := struct {
		Token string `json:"token"`
	}{
		Token: token,
	}

	payload, err := json.Marshal(authReq)
	if err != nil {
		return err
	}

	ok, response, err := conn.SendRequest("netbird-auth", true, payload)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("authentication rejected: %s", string(response))
	}

	return nil
}

// connectWithNetBirdClient connects to SSH server using NetBird's SSH client
func connectWithNetBirdClient(t *testing.T, host string, port int, privateKey []byte) (*client.Client, error) {
	t.Helper()
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	ctx := context.Background()
	return client.Dial(ctx, addr, getCurrentUsername(t), client.DialOptions{
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

	serverType, err := detection.DetectSSHServerType(host, port, "")
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

			config := &cryptossh.ClientConfig{
				User:            getCurrentUsername(t),
				Auth:            []cryptossh.AuthMethod{},
				HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			}

			conn, err := cryptossh.Dial("tcp", net.JoinHostPort(host, portStr), config)
			require.NoError(t, err)
			defer func() {
				if err := conn.Close(); err != nil {
					t.Logf("close connection: %v", err)
				}
			}()

			if tc.token == "valid" {
				token := generateValidJWT(t, privateKey, issuer, audience)
				err = sendJWTAuthRequest(conn, token)
				if tc.wantAuthOK {
					require.NoError(t, err, "JWT authentication should succeed")
				}
			} else if tc.token == "invalid" {
				invalidToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid"
				ok, _, err := conn.SendRequest("netbird-auth", true, []byte(`{"token":"`+invalidToken+`"}`))
				if err != nil {
					t.Logf("SendRequest error (expected): %v", err)
				}
				assert.False(t, ok, "Invalid JWT should be rejected")
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
