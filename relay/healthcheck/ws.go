package healthcheck

import (
	"context"
	"fmt"

	"github.com/coder/websocket"

	"github.com/netbirdio/netbird/shared/relay"
)

func dialWS(ctx context.Context, address string) error {
	url := fmt.Sprintf("wss://%s%s", address, relay.WebSocketURLPath)

	conn, resp, err := websocket.Dial(ctx, url, nil)
	if resp != nil {
		defer func() {
			_ = resp.Body.Close()
		}()

	}
	if err != nil {
		return fmt.Errorf("failed to connect to websocket: %w", err)
	}

	_ = conn.Close(websocket.StatusNormalClosure, "availability check complete")
	return nil
}
