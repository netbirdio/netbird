package store

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// SaveJob persists a job in DB
func (s *SqlStore) CreatePeerJob(ctx context.Context, job *types.Job) error {
	result := s.db.Create(job)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to create job in store")
	}
	return nil
}

func (s *SqlStore) CompletePeerJob(ctx context.Context, job *types.Job) error {
	result := s.db.
		Model(&types.Job{}).
		Where(idQueryCondition, job.ID).
		Updates(job)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to update job in store")
	}
	return nil
}

// job was pending for too long and has been cancelled
func (s *SqlStore) MarkPendingJobsAsFailed(ctx context.Context, accountID, peerID, jobID, reason string) error {
	now := time.Now().UTC()
	result := s.db.
		Model(&types.Job{}).
		Where(accountAndPeerIDQueryCondition+" AND id = ?"+" AND status = ?", accountID, peerID, jobID, types.JobStatusPending).
		Updates(types.Job{
			Status:       types.JobStatusFailed,
			FailedReason: reason,
			CompletedAt:  &now,
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to mark pending jobs as Failed job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to mark pending job as Failed in store")
	}
	return nil
}

// job was pending for too long and has been cancelled
func (s *SqlStore) MarkAllPendingJobsAsFailed(ctx context.Context, accountID, peerID, reason string) error {
	now := time.Now().UTC()
	result := s.db.
		Model(&types.Job{}).
		Where(accountAndPeerIDQueryCondition+" AND status = ?", accountID, peerID, types.JobStatusPending).
		Updates(types.Job{
			Status:       types.JobStatusFailed,
			FailedReason: reason,
			CompletedAt:  &now,
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to mark pending jobs as Failed job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to mark pending job as Failed in store")
	}
	return nil
}

// GetJobByID fetches job by ID
func (s *SqlStore) GetPeerJobByID(ctx context.Context, accountID, jobID string) (*types.Job, error) {
	var job types.Job
	err := s.db.
		Where(accountAndIDQueryCondition, accountID, jobID).
		First(&job).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "job %s not found", jobID)
	}
	if err != nil {
		log.WithContext(ctx).Errorf("failed to fetch job from store: %s", err)
		return nil, err
	}
	return &job, nil
}

// get all jobs
func (s *SqlStore) GetPeerJobs(ctx context.Context, accountID, peerID string) ([]*types.Job, error) {
	var jobs []*types.Job
	err := s.db.
		Where(accountAndPeerIDQueryCondition, accountID, peerID).
		Order("created_at DESC").
		Find(&jobs).Error
	if err != nil {
		log.WithContext(ctx).Errorf("failed to fetch jobs from store: %s", err)
		return nil, err
	}

	return jobs, nil
}
