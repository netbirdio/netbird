package server

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func (am *DefaultAccountManager) CreateJob(ctx context.Context, peerID string, job *proto.JobRequest) error {
	am.peersJobManager.CreateJob(ctx, peerID, job)
	am.peersJobManager.CloseRequestChannel(ctx, peerID)
	return nil
}
