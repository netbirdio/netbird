package server

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

const statusCoalesceWindow = 200 * time.Millisecond

// SubscribeStatus pushes a fresh StatusResponse on every connection state
// change. The first message is the current snapshot, so a re-subscribing
// client doesn't need to also call Status. Subsequent messages fire when
// the peer recorder reports any of: connected/disconnected/connecting,
// management or signal flip, address change, or peers list change.
//
// Bursts are coalesced deterministically: the first tick after a quiet
// period is sent immediately, then a short window swallows the rest of the
// burst and a single trailing snapshot covers whatever arrived meanwhile.
// Every send is a full snapshot of the recorder's current state, so
// swallowed ticks lose no information.
func (s *Server) SubscribeStatus(req *proto.StatusRequest, stream proto.DaemonService_SubscribeStatusServer) error {
	subID, ch := s.statusRecorder.SubscribeToStateChanges()
	defer func() {
		s.statusRecorder.UnsubscribeFromStateChanges(subID)
		log.Debug("client unsubscribed from status updates")
	}()

	log.Debug("client subscribed to status updates")

	if err := s.sendStatusSnapshot(req, stream); err != nil {
		return err
	}

	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return nil
			}
			if err := s.sendStatusSnapshot(req, stream); err != nil {
				return err
			}
			pending, open := collectStatusBurst(stream.Context(), ch)
			if pending {
				if err := s.sendStatusSnapshot(req, stream); err != nil {
					return err
				}
			}
			if !open {
				return nil
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// collectStatusBurst waits out the coalesce window, absorbing further ticks.
// pending reports whether any tick arrived; open is false when the channel
// closed or the stream context ended.
func collectStatusBurst(ctx context.Context, ch <-chan struct{}) (pending, open bool) {
	timer := time.NewTimer(statusCoalesceWindow)
	defer timer.Stop()
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return pending, false
			}
			pending = true
		case <-timer.C:
			return pending, true
		case <-ctx.Done():
			return false, false
		}
	}
}

func (s *Server) sendStatusSnapshot(req *proto.StatusRequest, stream proto.DaemonService_SubscribeStatusServer) error {
	resp, err := s.buildStatusResponse(stream.Context(), req)
	if err != nil {
		log.Warnf("build status snapshot for stream: %v", err)
		return err
	}
	if err := stream.Send(resp); err != nil {
		log.Warnf("send status snapshot to stream: %v", err)
		return err
	}
	return nil
}
