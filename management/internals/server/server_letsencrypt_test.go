package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme/autocert"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
)

func newLetsEncryptTestServer(address string) *BaseServer {
	srv := NewServer(&Config{NbConfig: &nbconfig.Config{}, MgmtPort: 8443, LetsEncryptListenAddress: address})
	srv.certManager = &autocert.Manager{}
	return srv
}

func TestServeLetsEncryptChallenges_Disabled(t *testing.T) {
	srv := newLetsEncryptTestServer("")

	require.NoError(t, srv.serveLetsEncryptChallenges(context.Background()))
	require.Nil(t, srv.certListener)
}

func TestServeLetsEncryptChallenges_CustomAddress(t *testing.T) {
	srv := newLetsEncryptTestServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = srv.certListener.Close()
		srv.wg.Wait()
	})

	require.NoError(t, srv.serveLetsEncryptChallenges(ctx))
	require.NotNil(t, srv.certListener)

	conn, err := net.DialTimeout("tcp", srv.certListener.Addr().String(), time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TestServeLetsEncryptChallenges_BindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = occupied.Close() })
	srv := newLetsEncryptTestServer(occupied.Addr().String())

	require.Error(t, srv.serveLetsEncryptChallenges(context.Background()))
	require.Nil(t, srv.certListener)
}
