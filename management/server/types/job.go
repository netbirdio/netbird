package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/proto"
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

const (
	// MaxJobReasonLength is the maximum length allowed for job failure reasons
	MaxJobReasonLength = 4096
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
	Type       JobType         `gorm:"column:workload_type;index;type:varchar(50)"`
	Parameters json.RawMessage `gorm:"type:json"`
	Result     json.RawMessage `gorm:"type:json"`
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
		if err := validateAndBuildBundleParams(req.Workload, &workload); err != nil {
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
		if err := j.buildBundleResponse(&wl); err != nil {
			return nil, status.Errorf(status.Internal, "failed to process job: %v", err.Error())
		}
		return &wl, nil

	default:
		return nil, status.Errorf(status.InvalidArgument, "unknown job type: %v", j.Workload.Type)
	}
}

func (j *Job) buildBundleResponse(wl *api.WorkloadResponse) error {
	var p api.BundleParameters
	if err := json.Unmarshal(j.Workload.Parameters, &p); err != nil {
		return fmt.Errorf("invalid parameters for bundle job: %w", err)
	}
	var r api.BundleResult
	if err := json.Unmarshal(j.Workload.Result, &r); err != nil {
		return fmt.Errorf("invalid result for bundle job: %w", err)
	}

	if err := wl.FromBundleWorkloadResponse(api.BundleWorkloadResponse{
		Type:       api.WorkloadTypeBundle,
		Parameters: p,
		Result:     r,
	}); err != nil {
		return fmt.Errorf("unknown job parameters: %v", err)
	}
	return nil
}

func validateAndBuildBundleParams(req api.WorkloadRequest, workload *Workload) error {
	bundle, err := req.AsBundleWorkloadRequest()
	if err != nil {
		return fmt.Errorf("invalid parameters for bundle job")
	}
	// validate bundle_for_time <= 5 minutes if BundleFor is enabled
	if bundle.Parameters.BundleFor && (bundle.Parameters.BundleForTime < 1 || bundle.Parameters.BundleForTime > 5) {
		return fmt.Errorf("bundle_for_time must be between 1 and 5, got %d", bundle.Parameters.BundleForTime)
	}
	// validate log-file-count ≥ 1 and ≤ 1000
	if bundle.Parameters.LogFileCount < 1 || bundle.Parameters.LogFileCount > 1000 {
		return fmt.Errorf("log-file-count must be between 1 and 1000, got %d", bundle.Parameters.LogFileCount)
	}

	workload.Parameters, err = json.Marshal(bundle.Parameters)
	if err != nil {
		return fmt.Errorf("failed to marshal workload parameters: %w", err)
	}
	workload.Result = []byte("{}")
	workload.Type = JobType(api.WorkloadTypeBundle)

	return nil
}

// ApplyResponse validates and maps a proto.JobResponse into the Job fields.
func (j *Job) ApplyResponse(resp *proto.JobResponse) error {
	if resp == nil {
		return nil
	}

	j.ID = string(resp.ID)
	now := time.Now().UTC()
	j.CompletedAt = &now
	switch resp.Status {
	case proto.JobStatus_succeeded:
		j.Status = JobStatusSucceeded
	case proto.JobStatus_failed:
		j.Status = JobStatusFailed
		if len(resp.Reason) > 0 {
			reason := string(resp.Reason)
			if len(resp.Reason) > MaxJobReasonLength {
				reason = string(resp.Reason[:MaxJobReasonLength]) + "... (truncated)"
			}
			j.FailedReason = fmt.Sprintf("Client error: '%s'", reason)
		}
		return nil
	default:
		return fmt.Errorf("unexpected job status: %v", resp.Status)
	}

	// Handle workload results (oneof)
	var err error
	switch r := resp.WorkloadResults.(type) {
	case *proto.JobResponse_Bundle:
		if j.Workload.Result, err = json.Marshal(r.Bundle); err != nil {
			return fmt.Errorf("failed to marshal workload results: %w", err)
		}
	default:
		return fmt.Errorf("unsupported workload response type: %T", r)
	}
	return nil
}

func (j *Job) ToStreamJobRequest() (*proto.JobRequest, error) {
	switch j.Workload.Type {
	case JobTypeBundle:
		return j.buildStreamBundleResponse()
	default:
		return nil, status.Errorf(status.InvalidArgument, "unknown job type: %v", j.Workload.Type)
	}
}

func (j *Job) buildStreamBundleResponse() (*proto.JobRequest, error) {
	var p api.BundleParameters
	if err := json.Unmarshal(j.Workload.Parameters, &p); err != nil {
		return nil, fmt.Errorf("invalid parameters for bundle job: %w", err)
	}
	return &proto.JobRequest{
		ID: []byte(j.ID),
		WorkloadParameters: &proto.JobRequest_Bundle{
			Bundle: &proto.BundleParameters{
				BundleFor:     p.BundleFor,
				BundleForTime: int64(p.BundleForTime),
				LogFileCount:  int32(p.LogFileCount),
				Anonymize:     p.Anonymize,
			},
		},
	}, nil
}
