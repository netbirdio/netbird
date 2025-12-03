package proxy

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
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/ssh/server"
	"github.com/netbirdio/netbird/client/ssh/testutil"
	nbjwt "github.com/netbirdio/netbird/shared/auth/jwt"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "ssh" {
		if os.Args[2] == "exec" {
			if len(os.Args) > 3 {
				cmd := os.Args[3]
				if cmd == "echo" && len(os.Args) > 4 {
					fmt.Fprintln(os.Stdout, os.Args[4])
					os.Exit(0)
				}
			}
			fmt.Fprintf(os.Stderr, "Test binary called as 'ssh exec' with args: %v - preventing infinite recursion\n", os.Args)
			os.Exit(1)
		}
	}

	code := m.Run()

	testutil.CleanupTestUsers()

	os.Exit(code)
}

func TestSSHProxy_verifyHostKey(t *testing.T) {
	t.Run("calls daemon to verify host key", func(t *testing.T) {
		mockDaemon := startMockDaemon(t)
		defer mockDaemon.stop()

		grpcConn, err := grpc.NewClient(mockDaemon.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer func() { _ = grpcConn.Close() }()

		proxy := &SSHProxy{
			daemonAddr:   mockDaemon.addr,
			daemonClient: proto.NewDaemonServiceClient(grpcConn),
		}

		testKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)
		testPubKey, err := nbssh.GeneratePublicKey(testKey)
		require.NoError(t, err)

		mockDaemon.setHostKey("test-host", testPubKey)

		err = proxy.verifyHostKey("test-host", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, mustParsePublicKey(t, testPubKey))
		assert.NoError(t, err)
	})

	t.Run("rejects unknown host key", func(t *testing.T) {
		mockDaemon := startMockDaemon(t)
		defer mockDaemon.stop()

		grpcConn, err := grpc.NewClient(mockDaemon.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer func() { _ = grpcConn.Close() }()

		proxy := &SSHProxy{
			daemonAddr:   mockDaemon.addr,
			daemonClient: proto.NewDaemonServiceClient(grpcConn),
		}

		unknownKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)
		unknownPubKey, err := nbssh.GeneratePublicKey(unknownKey)
		require.NoError(t, err)

		err = proxy.verifyHostKey("unknown-host", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, mustParsePublicKey(t, unknownPubKey))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer unknown-host not found in network")
	})
}

func TestSSHProxy_Connect(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// TODO: Windows test times out - user switching and command execution tested on Linux
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on Windows - covered by Linux tests")
	}

	const (
		issuer   = "https://test-issuer.example.com"
		audience = "test-audience"
	)

	jwksServer, privateKey, jwksURL := setupJWKSServer(t)
	defer jwksServer.Close()

	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	hostPubKey, err := nbssh.GeneratePublicKey(hostKey)
	require.NoError(t, err)

	serverConfig := &server.Config{
		HostKeyPEM: hostKey,
		JWT: &server.JWTConfig{
			Issuer:       issuer,
			Audience:     audience,
			KeysLocation: jwksURL,
		},
	}
	sshServer := server.New(serverConfig)
	sshServer.SetAllowRootLogin(true)

	sshServerAddr := server.StartTestServer(t, sshServer)
	defer func() { _ = sshServer.Stop() }()

	mockDaemon := startMockDaemon(t)
	defer mockDaemon.stop()

	host, portStr, err := net.SplitHostPort(sshServerAddr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	mockDaemon.setHostKey(host, hostPubKey)

	validToken := generateValidJWT(t, privateKey, issuer, audience)
	mockDaemon.setJWTToken(validToken)

	proxyInstance, err := New(mockDaemon.addr, host, port, nil, nil)
	require.NoError(t, err)

	clientConn, proxyConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	origStdin := os.Stdin
	origStdout := os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	stdinReader, stdinWriter, err := os.Pipe()
	require.NoError(t, err)
	stdoutReader, stdoutWriter, err := os.Pipe()
	require.NoError(t, err)

	os.Stdin = stdinReader
	os.Stdout = stdoutWriter

	go func() {
		_, _ = io.Copy(stdinWriter, proxyConn)
	}()
	go func() {
		_, _ = io.Copy(proxyConn, stdoutReader)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connectErrCh := make(chan error, 1)
	go func() {
		connectErrCh <- proxyInstance.Connect(ctx)
	}()

	sshConfig := &cryptossh.ClientConfig{
		User:            testutil.GetTestUsername(t),
		Auth:            []cryptossh.AuthMethod{},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}

	sshClientConn, chans, reqs, err := cryptossh.NewClientConn(clientConn, "test", sshConfig)
	require.NoError(t, err, "Should connect to proxy server")
	defer func() { _ = sshClientConn.Close() }()

	sshClient := cryptossh.NewClient(sshClientConn, chans, reqs)

	session, err := sshClient.NewSession()
	require.NoError(t, err, "Should create session through full proxy to backend")

	outputCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		output, err := session.Output("echo hello-from-proxy")
		outputCh <- output
		errCh <- err
	}()

	select {
	case output := <-outputCh:
		err := <-errCh
		require.NoError(t, err, "Command should execute successfully through proxy")
		assert.Contains(t, string(output), "hello-from-proxy", "Should receive command output through proxy")
	case <-time.After(3 * time.Second):
		t.Fatal("Command execution timed out")
	}

	_ = session.Close()
	_ = sshClient.Close()
	_ = clientConn.Close()
	cancel()
}

type mockDaemonServer struct {
	proto.UnimplementedDaemonServiceServer
	hostKeys map[string][]byte
	jwtToken string
}

func (m *mockDaemonServer) GetPeerSSHHostKey(ctx context.Context, req *proto.GetPeerSSHHostKeyRequest) (*proto.GetPeerSSHHostKeyResponse, error) {
	key, found := m.hostKeys[req.PeerAddress]
	return &proto.GetPeerSSHHostKeyResponse{
		Found:      found,
		SshHostKey: key,
	}, nil
}

func (m *mockDaemonServer) RequestJWTAuth(ctx context.Context, req *proto.RequestJWTAuthRequest) (*proto.RequestJWTAuthResponse, error) {
	return &proto.RequestJWTAuthResponse{
		CachedToken: m.jwtToken,
	}, nil
}

func (m *mockDaemonServer) WaitJWTToken(ctx context.Context, req *proto.WaitJWTTokenRequest) (*proto.WaitJWTTokenResponse, error) {
	return &proto.WaitJWTTokenResponse{
		Token: m.jwtToken,
	}, nil
}

type mockDaemon struct {
	addr   string
	server *grpc.Server
	impl   *mockDaemonServer
}

func startMockDaemon(t *testing.T) *mockDaemon {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	impl := &mockDaemonServer{
		hostKeys: make(map[string][]byte),
		jwtToken: "test-jwt-token",
	}

	grpcServer := grpc.NewServer()
	proto.RegisterDaemonServiceServer(grpcServer, impl)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	return &mockDaemon{
		addr:   listener.Addr().String(),
		server: grpcServer,
		impl:   impl,
	}
}

func (m *mockDaemon) setHostKey(addr string, pubKey []byte) {
	m.impl.hostKeys[addr] = pubKey
}

func (m *mockDaemon) setJWTToken(token string) {
	m.impl.jwtToken = token
}

func (m *mockDaemon) stop() {
	if m.server != nil {
		m.server.Stop()
	}
}

func mustParsePublicKey(t *testing.T, pubKeyBytes []byte) cryptossh.PublicKey {
	t.Helper()
	pubKey, _, _, _, err := cryptossh.ParseAuthorizedKey(pubKeyBytes)
	require.NoError(t, err)
	return pubKey
}

func setupJWKSServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey, string) {
	t.Helper()
	privateKey, jwksJSON := generateTestJWKS(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(jwksJSON); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))

	return server, privateKey, server.URL
}

func generateTestJWKS(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey
	n := publicKey.N.Bytes()
	e := publicKey.E

	jwk := nbjwt.JSONWebKey{
		Kty: "RSA",
		Kid: "test-key-id",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(n),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(e)).Bytes()),
	}

	jwks := nbjwt.Jwks{
		Keys: []nbjwt.JSONWebKey{jwk},
	}

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	return privateKey, jwksJSON
}

func generateValidJWT(t *testing.T, privateKey *rsa.PrivateKey, issuer, audience string) string {
	t.Helper()
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
