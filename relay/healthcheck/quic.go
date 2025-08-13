package healthcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"

	tlsnb "github.com/netbirdio/netbird/shared/relay/tls"
)

func dialQUIC(ctx context.Context, address string) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false, // Keep certificate validation enabled
		NextProtos:         []string{tlsnb.NBalpn},
	}

	conn, err := quic.DialAddr(ctx, address, tlsConfig, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		EnableDatagrams: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to QUIC server: %w", err)
	}

	_ = conn.CloseWithError(0, "availability check complete")
	return nil
}
