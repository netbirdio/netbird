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

const (
	undispatchedJobCondition = "status = ? AND dispatched_at IS NULL"
	// Jobs created before deadlines existed were already sent by the node that created
	// them, so they are never queued again; the sweeper fails them instead.
	queuedJobCondition     = undispatchedJobCondition + " AND deadline_at IS NOT NULL"
	dispatchedJobCondition = "status = ? AND dispatched_at IS NOT NULL"
)

// CreatePeerJob persists a job in DB
func (s *SqlStore) CreatePeerJob(ctx context.Context, job *types.Job) error {
	result := s.db.Create(job)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to create job in store")
	}
	return nil
}

// HasPendingPeerJob reports whether the peer has a job that is queued or running.
func (s *SqlStore) HasPendingPeerJob(ctx context.Context, accountID, peerID string) (bool, error) {
	var count int64
	result := s.db.Model(&types.Job{}).
		Where(accountAndPeerIDQueryCondition+" AND status = ?", accountID, peerID, types.JobStatusPending).
		Count(&count)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to count pending jobs in store: %s", result.Error)
		return false, status.Errorf(status.Internal, "failed to count pending jobs in store")
	}
	return count > 0, nil
}

// GetQueuedPeerJobs returns the peer's jobs that no management node has sent yet, oldest
// first.
func (s *SqlStore) GetQueuedPeerJobs(ctx context.Context, accountID, peerID string) ([]*types.Job, error) {
	var jobs []*types.Job
	err := s.db.
		Where(accountAndPeerIDQueryCondition+" AND "+queuedJobCondition, accountID, peerID, types.JobStatusPending).
		Order("created_at ASC").
		Find(&jobs).Error
	if err != nil {
		log.WithContext(ctx).Errorf("failed to fetch queued jobs from store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to fetch queued jobs from store")
	}
	return jobs, nil
}

// ClaimPeerJob marks a queued job as sent and moves its deadline. It reports false when
// the job is no longer queued, so of several nodes trying at once only one sends it.
func (s *SqlStore) ClaimPeerJob(ctx context.Context, accountID, peerID, jobID string, dispatchedAt, deadlineAt time.Time) (bool, error) {
	result := s.db.Model(&types.Job{}).
		Where(accountAndPeerIDQueryCondition+" AND id = ? AND "+queuedJobCondition, accountID, peerID, jobID, types.JobStatusPending).
		Updates(map[string]any{"dispatched_at": dispatchedAt, "deadline_at": deadlineAt})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to claim job in store: %s", result.Error)
		return false, status.Errorf(status.Internal, "failed to claim job in store")
	}
	return result.RowsAffected == 1, nil
}

// CompleteDispatchedPeerJob records the outcome of a job sent to the peer. It reports
// false when the job is not a running job of that peer, for example when the answer
// arrives after the deadline or for another peer's job.
func (s *SqlStore) CompleteDispatchedPeerJob(ctx context.Context, accountID, peerID string, job *types.Job) (bool, error) {
	result := s.db.Model(&types.Job{}).
		Where(accountAndPeerIDQueryCondition+" AND id = ? AND "+dispatchedJobCondition, accountID, peerID, job.ID, types.JobStatusPending).
		Updates(map[string]any{
			"status":          job.Status,
			"failed_reason":   job.FailedReason,
			"completed_at":    job.CompletedAt,
			"workload_result": job.Workload.Result,
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to complete job in store: %s", result.Error)
		return false, status.Errorf(status.Internal, "failed to complete job in store")
	}
	return result.RowsAffected == 1, nil
}

// FailDispatchedPeerJobs fails the peer's jobs that were sent but not answered.
func (s *SqlStore) FailDispatchedPeerJobs(ctx context.Context, accountID, peerID, reason string) error {
	result := s.db.Model(&types.Job{}).
		Where(accountAndPeerIDQueryCondition+" AND "+dispatchedJobCondition, accountID, peerID, types.JobStatusPending).
		Updates(failedJobColumns(reason))
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to fail dispatched jobs in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to fail dispatched jobs in store")
	}
	return nil
}

// FailExpiredPeerJobs fails pending jobs past their deadline, with a reason per stage.
// Jobs created before deadlines existed count as expired once created before
// legacyCreatedBefore.
func (s *SqlStore) FailExpiredPeerJobs(ctx context.Context, now, legacyCreatedBefore time.Time, queuedReason, dispatchedReason string) (int64, error) {
	queued := s.db.Model(&types.Job{}).
		Where(undispatchedJobCondition, types.JobStatusPending).
		Where("(deadline_at < ? OR (deadline_at IS NULL AND created_at < ?))", now, legacyCreatedBefore).
		Updates(failedJobColumns(queuedReason))
	if queued.Error != nil {
		log.WithContext(ctx).Errorf("failed to fail expired queued jobs in store: %s", queued.Error)
		return 0, status.Errorf(status.Internal, "failed to fail expired jobs in store")
	}

	dispatched := s.db.Model(&types.Job{}).
		Where(dispatchedJobCondition+" AND deadline_at < ?", types.JobStatusPending, now).
		Updates(failedJobColumns(dispatchedReason))
	if dispatched.Error != nil {
		log.WithContext(ctx).Errorf("failed to fail expired dispatched jobs in store: %s", dispatched.Error)
		return queued.RowsAffected, status.Errorf(status.Internal, "failed to fail expired jobs in store")
	}

	return queued.RowsAffected + dispatched.RowsAffected, nil
}

func failedJobColumns(reason string) map[string]any {
	return map[string]any{
		"status":        types.JobStatusFailed,
		"failed_reason": reason,
		"completed_at":  time.Now().UTC(),
	}
}

// GetPeerJobByID fetches one job of a peer.
func (s *SqlStore) GetPeerJobByID(ctx context.Context, accountID, peerID, jobID string) (*types.Job, error) {
	var job types.Job
	err := s.db.
		Where(accountAndPeerIDQueryCondition+" AND id = ?", accountID, peerID, jobID).
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
