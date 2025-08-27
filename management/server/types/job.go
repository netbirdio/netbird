package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/shared/management/http/api"
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
	JobTypeOther  JobType = "other"
	// add more job types here
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

	// Type of the job, e.g. "bundle"
	Type JobType `gorm:"index;type:varchar(50)"`

	// Status of the job: pending, succeeded, failed
	Status JobStatus `gorm:"index;type:varchar(50)"`

	// FailedReason describes why the job failed (if failed)
	FailedReason string

	// Result can contain job output (JSON, URL, etc.)
	Result json.RawMessage `gorm:"type:json"`

	// Parameters is a JSON blob storing job configuration (untyped)
	Parameters json.RawMessage `gorm:"type:json"`
}

// NewJob creates a new job with default fields and validation
func NewJob(triggeredBy, accountID, peerID string, req *api.JobRequest) (*Job, error) {
	if req == nil {
		return nil, fmt.Errorf("job request cannot be nil")
	}

	// Determine job type
	jobTypeStr, err := req.Workload.Discriminator()
	if err != nil {
		return nil, fmt.Errorf("could not determine job type: %w", err)
	}
	jobType := JobType(jobTypeStr)

	var params []byte

	switch jobType {
	case JobTypeBundle:
		params, err = validateDebugBundleJobParams(req.Workload)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported job type: %s", jobType)
	}

	return &Job{
		ID:          uuid.New().String(),
		TriggeredBy: triggeredBy,
		PeerID:      peerID,
		AccountID:   accountID,
		Type:        jobType,
		Status:      JobStatusPending,
		Parameters:  params,
		CreatedAt:   time.Now().UTC(),
		Result:      []byte("{}"),
	}, nil
}

func (j *Job) BuildWorkloadResponse(wl *api.WorkloadResponse) error {
	switch j.Type {
	case JobTypeBundle:
		return j.buildBundleWorkload(wl)
	case JobTypeOther:
		return j.buildOtherWorkload(wl)
	default:
		return fmt.Errorf("unknown job type: %v", j.Type)
	}
}

func (j *Job) buildBundleWorkload(wl *api.WorkloadResponse) error {
	var p api.BundleParameters

	if err := json.Unmarshal(j.Parameters, &p); err != nil {
		return fmt.Errorf("invalid parameters for bundle job: %w", err)
	}

	var r api.BundleResult
	if err := json.Unmarshal(j.Result, &r); err != nil {
		return fmt.Errorf("invalid result for bundle job: %w", err)
	}

	return wl.FromBundleWorkloadResponse(api.BundleWorkloadResponse{
		Type:       api.WorkloadTypeBundle,
		Parameters: p,
		Result:     r,
	})
}

func (j *Job) buildOtherWorkload(wl *api.WorkloadResponse) error {
	var p api.OtherParameters
	if err := json.Unmarshal(j.Parameters, &p); err != nil {
		return fmt.Errorf("invalid parameters for bundle job: %w", err)
	}

	var r api.OtherResult
	if err := json.Unmarshal(j.Result, &r); err != nil {
		return fmt.Errorf("invalid result for bundle job: %w", err)
	}

	return wl.FromOtherWorkloadResponse(api.OtherWorkloadResponse{
		Type:       api.WorkloadTypeOther,
		Parameters: p,
		Result:     r,
	})
}

func validateDebugBundleJobParams(req api.WorkloadRequest) ([]byte, error) {
	bundle, err := req.AsBundleWorkloadRequest()
	if err != nil {
		return nil, fmt.Errorf("invalid parameters for bundle job: %w", err)
	}
	// validate bundle_for_time <= 5 minutes
	if bundle.Parameters.BundleForTime < 0 || bundle.Parameters.BundleForTime > 5 {
		return nil, fmt.Errorf("bundle_for_time must be between 0 and 5, got %d", bundle.Parameters.BundleForTime)
	}
	// validate log-file-count ≥ 1 and ≤ 1000
	if bundle.Parameters.LogFileCount < 1 || bundle.Parameters.LogFileCount > 1000 {
		return nil, fmt.Errorf("log-file-count must be between 1 and 1000, got %d", bundle.Parameters.LogFileCount)
	}

	params, err := json.Marshal(bundle.Parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal workload parameters: %w", err)
	}
	return params, nil
}
