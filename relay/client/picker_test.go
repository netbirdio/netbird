package client

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServerPicker_UnavailableServers(t *testing.T) {
	sp := ServerPicker{
		TokenStore: nil,
		PeerID:     "test",
	}
	sp.ServerURLs.Store([]string{"rel://dummy1", "rel://dummy2"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		_, err := sp.PickServer(ctx)
		if err == nil {
			t.Error(err)
		}
		cancel()
	}()

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Errorf("PickServer() took too long to complete")
	}
}
