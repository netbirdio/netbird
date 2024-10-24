package server

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// restoreResidualConfig checks if the client was not shut down in a clean way and restores residual state if required.
// Otherwise, we might not be able to connect to the management server to retrieve new config.
func restoreResidualState(ctx context.Context) error {
	path := statemanager.GetDefaultStatePath()
	if path == "" {
		return nil
	}

	mgr := statemanager.New(path)

	// register the states we are interested in restoring
	registerStates(mgr)

	var merr *multierror.Error
	if err := mgr.PerformCleanup(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("perform cleanup: %w", err))
	}

	// persist state regardless of cleanup outcome. It could've succeeded partially
	if err := mgr.PersistState(ctx); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("persist state: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}
