package server

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// NotifySleep handles sleep event notifications from the UI
func (s *Server) NotifySleep(ctx context.Context, req *proto.NotifySleepRequest) (*proto.NotifySleepResponse, error) {
	log.Debugf("received sleep event notification")

	engine := s.connectClient.Engine()
	if engine == nil {
		log.Warnf("failed to get engine, sleep event unhandled")
		return nil, fmt.Errorf("engine not initialized")
	}

	engine.PrepareSleep()
	return &proto.NotifySleepResponse{}, nil
}
