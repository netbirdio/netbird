package jobexec

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/upload-server/types"
)

const (
	MaxBundleWaitTime = 60 * time.Minute // maximum wait time for bundle generation (1 hour)
)

var (
	ErrJobNotImplemented = errors.New("job not implemented")
)

type Executor struct {
}

func NewExecutor() *Executor {
	return &Executor{}
}

func (e *Executor) BundleJob(ctx context.Context, debugBundleDependencies debug.GeneratorDependencies, params debug.BundleConfig, waitForDuration time.Duration, mgmURL string) (string, error) {
	if waitForDuration > MaxBundleWaitTime {
		log.Warnf("bundle wait time %v exceeds maximum %v, capping to maximum", waitFor, MaxBundleWaitTime)
		waitForDuration = MaxBundleWaitTime
	}

	if waitForDuration > 0 {
		waitFor(ctx, waitForDuration)
	}

	log.Infof("execute debug bundle generation")

	bundleGenerator := debug.NewBundleGenerator(debugBundleDependencies, params)

	path, err := bundleGenerator.Generate()
	if err != nil {
		return "", fmt.Errorf("generate debug bundle: %w", err)
	}

	key, err := debug.UploadDebugBundle(ctx, types.DefaultBundleURL, mgmURL, path)
	if err != nil {
		log.Errorf("failed to upload debug bundle to %v", err)
		return "", fmt.Errorf("upload debug bundle: %w", err)
	}

	log.Infof("debug bundle has been generated well")
	return key, nil
}

func waitFor(ctx context.Context, duration time.Duration) {
	log.Infof("wait for %v minutes before executing debug bundle", duration.Minutes())
	select {
	case <-time.After(duration):
	case <-ctx.Done():
		log.Infof("wait cancelled: %v", ctx.Err())
	}
}
