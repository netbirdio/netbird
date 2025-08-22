package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
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
	Result string

	// Parameters is a JSON blob storing job configuration (untyped)
	Parameters json.RawMessage `gorm:"type:json"`
}

// JobParametersBundle represents parameters for bundle/debug jobs
type JobParametersBundle struct {
	BundleFor     bool `json:"bundle_for"`
	BundleForTime int  `json:"bundle_for_time"` // minutes
	LogFileCount  int  `json:"log_file_count"`
	Anonymize     bool `json:"anonymize"`
}

// NewJob creates a new job with default fields and validation
func NewJob(triggeredBy, accountID, peerID string, jobType JobType, parameters map[string]any) (*Job, error) {
	job := &Job{
		ID:          uuid.New().String(),
		TriggeredBy: triggeredBy,
		PeerID:      peerID,
		AccountID:   accountID,
		Type:        jobType,
		Status:      JobStatusPending,
		CreatedAt:   time.Now().UTC(),
	}

	// Encode parameters
	if err := job.encodeParameters(parameters); err != nil {
		return nil, fmt.Errorf("failed to encode job parameters: %w", err)
	}

	// Validate job
	if err := job.validateJobRequest(); err != nil {
		return nil, err
	}

	return job, nil
}

// DecodeParameters decodes raw parameters into a target struct
func (j *Job) DecodeParameters(target any) error {
	if len(j.Parameters) == 0 {
		return nil
	}
	return json.Unmarshal(j.Parameters, target)
}

// EncodeParameters replaces raw parameters with marshaled JSON
func (j *Job) encodeParameters(params map[string]any) error {
	if params == nil {
		return fmt.Errorf("parameters cannot be empty")
	}
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	j.Parameters = data
	return nil
}

func (j *Job) validateJobRequest() error {
	if j == nil {
		return fmt.Errorf("job cannot be nil")
	}

	if len(j.Parameters) == 0 {
		return fmt.Errorf("job parameters must be provided")
	}

	switch j.Type {
	case JobTypeBundle:
		if err := j.validateDebugBundleJobParams(); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported job type: %s", j.Type)
	}

	return nil
}

func (j *Job) validateDebugBundleJobParams() error {
	var params JobParametersBundle
	if err := j.DecodeParameters(&params); err != nil {
		return fmt.Errorf("invalid parameters for bundle job: %w", err)
	}
	// validate bundle_for_time <= 5 minutes
	if params.BundleForTime < 0 || params.BundleForTime > 5 {
		return fmt.Errorf("bundle_for_time must be between 0 and 5, got %d", params.BundleForTime)
	}

	// validate log-file-count ≥ 1 and ≤ 1000
	if params.LogFileCount < 1 || params.LogFileCount > 1000 {
		return fmt.Errorf("log-file-count must be between 1 and 1000, got %d", params.LogFileCount)
	}
	return nil
}
