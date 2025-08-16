package server

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func (am *DefaultAccountManager) CreateJob(ctx context.Context, peerID string, job *proto.JobRequest) error {
	return am.jobManager.SendJob(ctx, peerID, job)
}

func (am *DefaultAccountManager) GetJob(ctx context.Context, jobID string) (*proto.JobResponse, error) {
	return am.jobManager.GetJobResponse(jobID)
}
