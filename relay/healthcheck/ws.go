package healthcheck

import (
	"context"
	"fmt"
	"strings"

	"github.com/coder/websocket"

	"github.com/netbirdio/netbird/shared/relay"
)

func dialWS(ctx context.Context, address string) error {
	addressSplit := strings.Split(address, "/")
	scheme := "ws"
	if addressSplit[0] == "rels:" {
		scheme = "wss"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, addressSplit[2], relay.WebSocketURLPath)

	conn, resp, err := websocket.Dial(ctx, url, nil)
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
