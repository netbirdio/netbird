package server

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
)

func (s *Server) SubscribeEvents(req *proto.SubscribeRequest, stream proto.DaemonService_SubscribeEventsServer) error {
	subscription := s.statusRecorder.SubscribeToEvents()
	defer func() {
		s.statusRecorder.UnsubscribeFromEvents(subscription)
		log.Debug("client unsubscribed from events")
	}()

	log.Debug("client subscribed to events")
	s.startUpdateManagerForGUI()

	// Replay the current log level to this subscriber so a freshly-connected UI
	// learns it even when the daemon was already started with --log-level debug
	// (the change-driven publishLogLevelChanged only fires on SetLogLevel). Sent
	// directly on this stream rather than via PublishEvent so it reaches only
	// the new subscriber, not every connected client.
	if err := s.sendCurrentLogLevel(stream); err != nil {
		return err
	}

	for {
		select {
		case event := <-subscription.Events():
			if err := stream.Send(event); err != nil {
				log.Warnf("error sending event to %v: %v", req, err)
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// sendCurrentLogLevel sends a marked log-level-changed SystemEvent carrying the
// daemon's current level directly to one subscriber. Mirrors the shape
// publishLogLevelChanged emits so the UI's dispatchSystemEvent handles both the
// same way.
func (s *Server) sendCurrentLogLevel(stream proto.DaemonService_SubscribeEventsServer) error {
	level := log.GetLevel().String()
	event := &proto.SystemEvent{
		Id:        uuid.New().String(),
		Severity:  proto.SystemEvent_INFO,
		Category:  proto.SystemEvent_SYSTEM,
		Message:   "Log level changed",
		Metadata:  map[string]string{proto.MetadataKindKey: proto.MetadataKindLogLevelChanged, proto.MetadataLevelKey: level},
		Timestamp: timestamppb.Now(),
	}
	if err := stream.Send(event); err != nil {
		log.Warnf("error sending initial log level event: %v", err)
		return err
	}
	return nil
}
