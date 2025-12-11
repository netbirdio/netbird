package healthcheck

import (
	"context"
	"fmt"
	"net/url"

	"github.com/coder/websocket"

	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/relay"
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

	_ = conn.Close(websocket.StatusNormalClosure, "availability check complete")
	return nil
}
