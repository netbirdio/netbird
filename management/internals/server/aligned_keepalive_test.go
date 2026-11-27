package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

// recordingListener records every accepted connection, so a test can read
// the server socket of a stream.
type recordingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.conns = append(l.conns, c)
	l.mu.Unlock()
	return c, nil
}

func (l *recordingListener) accepted() net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) == 0 {
		return nil
	}
	return l.conns[0]
}

// alignedSyncServer is a ManagementService whose Sync stream sets the
// aligned keepalive the way PeerUpdateHandler does, then blocks.
type alignedSyncServer struct {
	mgmtProto.UnimplementedManagementServiceServer
	applied chan error
}

func (s *alignedSyncServer) Sync(_ *mgmtProto.EncryptedMessage, srv mgmtProto.ManagementService_SyncServer) error {
	s.applied <- keepalive.SetAlignedStream(srv.Context(), 30*time.Second)
	<-srv.Context().Done()
	return nil
}

// selfSignedTLS returns a server TLS config for 127.0.0.1 that offers h2,
// and a client pool that trusts it.
func selfSignedTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	}, pool
}

// Through both branches of the real serveGRPCWithHTTP path (TLS and h2c) an
// aligned stream must reach its accepted socket: the server conn gets the
// aligned idle, not ErrNoConn. This proves only the ConnContext wiring; the
// aligned answer and heartbeat are proven in the grpc package tests.
func TestServeGRPCWithHTTPAlignedStreamKeepAlive(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	for _, tlsEnabled := range []bool{true, false} {
		name := "h2c"
		if tlsEnabled {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			rec := &recordingListener{Listener: ln}
			t.Cleanup(func() { _ = ln.Close() })

			var serveLn net.Listener = rec
			creds := insecure.NewCredentials()
			if tlsEnabled {
				serverTLS, pool := selfSignedTLS(t)
				serveLn = tls.NewListener(rec, serverTLS)
				creds = credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
			}

			grpcServer := grpc.NewServer()
			fake := &alignedSyncServer{applied: make(chan error, 1)}
			mgmtProto.RegisterManagementServiceServer(grpcServer, fake)
			t.Cleanup(grpcServer.Stop)

			base := &BaseServer{}
			base.serveGRPCWithHTTP(context.Background(), serveLn, grpcServer, tlsEnabled)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := grpc.NewClient(rec.Addr().String(), grpc.WithTransportCredentials(creds))
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()

			_, err = mgmtProto.NewManagementServiceClient(conn).Sync(ctx, &mgmtProto.EncryptedMessage{})
			require.NoError(t, err)

			select {
			case err := <-fake.applied:
				require.NoError(t, err, "the stream context must carry the accepted connection")
			case <-time.After(5 * time.Second):
				t.Fatal("Sync stream was not handled within 5s")
			}

			serverConn := rec.accepted()
			require.NotNil(t, serverConn, "the serve path must accept a connection")
			assert.Eventually(t, func() bool {
				idle, err := keepalive.Idle(serverConn)
				return err == nil && idle == 60*time.Second
			}, 2*time.Second, 10*time.Millisecond, "aligned stream: idle twice the 30s period")
		})
	}
}
