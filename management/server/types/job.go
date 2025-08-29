package types

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusSucceeded JobStatus = "succeeded"
	JobStatusFailed    JobStatus = "failed"
)

type JobType string

const (
	JobTypeBundle JobType = "bundle"
)

type Job struct {
	// ID is the primary identifier
	ID string `gorm:"primaryKey"`

	// CreatedAt when job was created (UTC)
	CreatedAt time.Time `gorm:"autoCreateTime"`

	// CompletedAt when job finished, null if still running
	CompletedAt *time.Time

	// TriggeredBy user that triggered this job
	TriggeredBy string `gorm:"index"`

	PeerID string `gorm:"index"`

	AccountID string `gorm:"index"`

	// Status of the job: pending, succeeded, failed
	Status JobStatus `gorm:"index;type:varchar(50)"`

	// FailedReason describes why the job failed (if failed)
	FailedReason string

	Workload Workload `gorm:"embedded;embeddedPrefix:workload_"`
}

type Workload struct {
	Type JobType `gorm:"column:workload_type;index;type:varchar(50)"`

	// Only one branch is valid depending on Type. The other branch stays zero-valued.
	BundleParameters *api.BundleParameters `gorm:"embedded" json:"-"`
	BundleResult     *api.BundleResult     `gorm:"embedded" json:"-"`

	// OTHER Jobs

}

// NewJob creates a new job with default fields and validation
func NewJob(triggeredBy, accountID, peerID string, req *api.JobRequest) (*Job, error) {
	if req == nil {
		return nil, status.Errorf(status.BadRequest, "job request cannot be nil")
	}

	// Determine job type
	jobTypeStr, err := req.Workload.Discriminator()
	if err != nil {
		return nil, status.Errorf(status.BadRequest, "could not determine job type: %v", err)
	}
	jobType := JobType(jobTypeStr)

	if jobType == "" {
		return nil, status.Errorf(status.BadRequest, "job type is required")
	}

	var workload Workload

	switch jobType {
	case JobTypeBundle:
		if err := validateBundleParams(req.Workload, &workload); err != nil {
			return nil, status.Errorf(status.BadRequest, "%v", err)
		}
	default:
		return nil, status.Errorf(status.BadRequest, "unsupported job type: %s", jobType)
	}

	return &Job{
		ID:          uuid.New().String(),
		TriggeredBy: triggeredBy,
		PeerID:      peerID,
		AccountID:   accountID,
		Status:      JobStatusPending,
		CreatedAt:   time.Now().UTC(),
		Workload:    workload,
	}, nil
}

func (j *Job) BuildWorkloadResponse() (*api.WorkloadResponse, error) {
	var wl api.WorkloadResponse

	switch j.Workload.Type {
	case JobTypeBundle:
		if j.Workload.BundleParameters == nil {
			return nil, status.Errorf(status.InvalidArgument, "missing bundle parameters")
		}
		if err := wl.FromBundleWorkloadResponse(api.BundleWorkloadResponse{
			Type:       api.WorkloadTypeBundle,
			Parameters: *j.Workload.BundleParameters,
			Result:     *j.Workload.BundleResult,
		}); err != nil {
			return nil, status.Errorf(status.InvalidArgument, "unknown job parameters: %v", err)
		}
		return &wl, nil

	default:
		return nil, status.Errorf(status.InvalidArgument, "unknown job type: %v", j.Workload.Type)
	}
}

func validateBundleParams(req api.WorkloadRequest, workload *Workload) error {
	bundle, err := req.AsBundleWorkloadRequest()
	if err != nil {
		return fmt.Errorf("invalid parameters for bundle job")
	}
	// validate bundle_for_time <= 5 minutes
	if bundle.Parameters.BundleForTime < 0 || bundle.Parameters.BundleForTime > 5 {
		return fmt.Errorf("bundle_for_time must be between 0 and 5, got %d", bundle.Parameters.BundleForTime)
	}
	// validate log-file-count ≥ 1 and ≤ 1000
	if bundle.Parameters.LogFileCount < 1 || bundle.Parameters.LogFileCount > 1000 {
		return fmt.Errorf("log-file-count must be between 1 and 1000, got %d", bundle.Parameters.LogFileCount)
	}
	workload.BundleParameters = &bundle.Parameters
	workload.BundleResult = &api.BundleResult{}
	workload.Type = JobTypeBundle
	return nil
}
