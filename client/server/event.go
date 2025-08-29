package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

func (s *Server) SubscribeEvents(req *proto.SubscribeRequest, stream proto.DaemonService_SubscribeEventsServer) error {
	subscription := s.statusRecorder.SubscribeToEvents()
	defer func() {
		s.statusRecorder.UnsubscribeFromEvents(subscription)
		log.Debug("client unsubscribed from events")
	}()

	log.Debug("client subscribed to events")

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

func (s *Server) GetEvents(context.Context, *proto.GetEventsRequest) (*proto.GetEventsResponse, error) {
	events := s.statusRecorder.GetEventHistory()
	return &proto.GetEventsResponse{Events: events}, nil
}
