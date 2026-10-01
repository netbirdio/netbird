package healthcheck

import (
	"context"
	"fmt"
	"net/url"

	"github.com/coder/websocket"

	"github.com/netbirdio/netbird/relay/healthcheck/peerid"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/relay"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func dialWS(ctx context.Context, address url.URL) error {
	scheme := "ws"
	if address.Scheme == server.SchemeRELS {
		scheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s%s", scheme, address.Host, relay.WebSocketURLPath)

	conn, resp, err := websocket.Dial(ctx, wsURL, nil)
	if resp != nil {
		defer func() {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
		}()

	}
	if err != nil {
		return fmt.Errorf("failed to connect to websocket: %w", err)
	}
	defer func() {
		_ = conn.CloseNow()
	}()

	authMsg, err := messages.MarshalAuthMsg(peerid.HealthCheckPeerID, peerid.DummyAuthToken)
	if err != nil {
		return fmt.Errorf("failed to marshal auth message: %w", err)
	}

	if err := conn.Write(ctx, websocket.MessageBinary, authMsg); err != nil {
		return fmt.Errorf("failed to write auth message: %w", err)
	}

	return nil
}
