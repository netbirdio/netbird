package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	client "github.com/netbirdio/netbird/shared/management/client"
)

// TestNewClientWithCert_RejectsUnreachableAddr verifies that NewClientWithCert
// fails fast when the address is unreachable.
func TestNewClientWithCert_RejectsUnreachableAddr(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)
	tlsCert := &tls.Certificate{
		PrivateKey:  privKey,
		Certificate: [][]byte{certDER},
		Leaf:        cert,
	}

	wgKey, _ := wgtypes.GeneratePrivateKey()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 127.0.0.1:1 — nothing listening, dial will fail within the timeout.
	_, err := client.NewClientWithCert(ctx, "127.0.0.1:1", wgKey, tlsCert)
	require.Error(t, err, "expected connection failure to unreachable address")
}
