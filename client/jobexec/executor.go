package jobexec

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/upload-server/types"
)

type Executor struct {
}

func NewExecutor() *Executor {
	return &Executor{}
}

func (e *Executor) BundleJob(ctx context.Context, debugBundleDependencies debug.GeneratorDependencies, params debug.BundleConfig, mgmURL string) (string, error) {
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

	return key, nil
}
