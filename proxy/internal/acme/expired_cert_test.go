package acme

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// autocert serves the certificate it holds in memory without checking its
// expiry. Once it has expired and renewal keeps failing, the proxy must
// report the expiry, and must serve a valid certificate as soon as one is in
// the cache (renewed by another replica sharing the cert dir).
func TestExpiredCertificate_ReportedAndReplacedFromCache(t *testing.T) {
	mgr, _, _, _, logs := startRenewalProxy(t, 2*time.Second)
	ctx := context.Background()
	hello := ecdsaHello(ctx, renewalTestDomain)

	cert, err := mgr.GetCertificate(hello)
	require.NoError(t, err)
	time.Sleep(time.Until(cert.Leaf.NotAfter) + 100*time.Millisecond)

	cert, err = mgr.GetCertificate(hello)
	require.NoError(t, err)
	require.True(t, time.Now().After(cert.Leaf.NotAfter), "precondition: only the expired certificate exists")

	mgr.checkExpiry(ctx, time.Now())
	assert.Contains(t, logs.String(), "level=error", "the expiry must be logged")
	assert.Contains(t, mgr.FailedDomains(), renewalTestDomain, "the expiry must mark the domain failed")

	writeCachedCert(t, mgr.certDir, renewalTestDomain, 10*24*time.Hour)
	cert, err = mgr.GetCertificate(hello)
	require.NoError(t, err)
	assert.True(t, time.Now().Before(cert.Leaf.NotAfter),
		"served a certificate that expired at %s although a valid one is in the cache", cert.Leaf.NotAfter)

	mgr.checkExpiry(ctx, time.Now())
	assert.Contains(t, mgr.ReadyDomains(), renewalTestDomain, "a valid certificate in the cache makes the domain ready again")
}
