package manager

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/shared/management/status"
	log "github.com/sirupsen/logrus"
)

const (
	exposeTTL          = 90 * time.Second
	exposeReapInterval = 30 * time.Second
	maxExposesPerPeer  = 10
	exposeReapBatch    = 100
)

type exposeReaper struct {
	manager *Manager
}

// StartExposeReaper starts a background goroutine that reaps expired ephemeral services from the DB.
func (r *exposeReaper) StartExposeReaper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(exposeReapInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.reapExpiredExposes(ctx)
			}
		}
	}()
}

func (r *exposeReaper) reapExpiredExposes(ctx context.Context) {
	expired, err := r.manager.store.GetExpiredEphemeralServices(ctx, exposeTTL, exposeReapBatch)
	if err != nil {
		log.Errorf("failed to get expired ephemeral services: %v", err)
		return
	}

	for _, svc := range expired {
		log.Infof("reaping expired expose session for peer %s, domain %s", svc.SourcePeer, svc.Domain)

		err := r.manager.deleteExpiredPeerService(ctx, svc.AccountID, svc.SourcePeer, svc.ID)
		s, _ := status.FromError(err)

		switch {
		case err == nil:
			// successfully deleted
		case s.ErrorType == status.NotFound:
			log.Debugf("service %s was already deleted by another instance", svc.Domain)
		default:
			log.Errorf("failed to delete expired peer-exposed service for domain %s: %v", svc.Domain, err)
		}
	}
}
