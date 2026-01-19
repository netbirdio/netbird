package jobexec

import (
	"context"
	"errors"
	"fmt"
	"os"
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
		log.Warnf("bundle wait time %v exceeds maximum %v, capping to maximum", waitForDuration, MaxBundleWaitTime)
		waitForDuration = MaxBundleWaitTime
	}

	if waitForDuration > 0 {
		if err := waitFor(ctx, waitForDuration); err != nil {
			return "", err
		}
	}

	log.Infof("execute debug bundle generation")

	bundleGenerator := debug.NewBundleGenerator(debugBundleDependencies, params)

	path, err := bundleGenerator.Generate()
	if err != nil {
		return "", fmt.Errorf("generate debug bundle: %w", err)
	}
	defer func() {
		if err := os.Remove(path); err != nil {
			log.Errorf("failed to remove debug bundle file: %v", err)
		}
	}()

	key, err := debug.UploadDebugBundle(ctx, types.DefaultBundleURL, mgmURL, path)
	if err != nil {
		log.Errorf("failed to upload debug bundle: %v", err)
		return "", fmt.Errorf("upload debug bundle: %w", err)
	}

	log.Infof("debug bundle has been generated successfully")
	return key, nil
}

func waitFor(ctx context.Context, duration time.Duration) error {
	log.Infof("wait for %v minutes before executing debug bundle", duration.Minutes())
	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		log.Infof("wait cancelled: %v", ctx.Err())
		return ctx.Err()
	}
}
