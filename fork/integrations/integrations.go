// SPDX-License-Identifier: BSD-3-Clause

// Package integrations mirrors the upstream management-integrations module 1:1
// and adds the flow logger wiring on top. Surface changes upstream must fail
// loudly at compile time rather than silently changing behavior, so every
// exported symbol of the original module is kept with an identical signature.
package integrations

import (
	"context"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/util/crypt"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
)

// RegisterHandlers registers extra HTTP handlers of the closed-source
// integrations on the API router. As in the original module this is a no-op;
// the flow receiver is a separate process and needs no management endpoints.
func RegisterHandlers(
	ctx context.Context,
	prefix string,
	router *mux.Router,
	accountManager account.Manager,
	integratedValidator integrated_validator.IntegratedValidator,
	meter metric.Meter,
	permissionsManager permissions.Manager,
	peersManager peers.Manager,
	proxyController port_forwarding.Controller,
	settingsManager settings.Manager,
) (*mux.Router, error) {
	return router, nil
}

// InitEventStore initializes the activity event store, mirroring the original
// module behavior of generating a new key when none is configured.
func InitEventStore(ctx context.Context, dataDir string, key string, _ *Metrics) (activity.Store, string, error) {
	var err error
	if key == "" {
		log.Debugf("generate new activity store encryption key")
		key, err = crypt.GenerateKey()
		if err != nil {
			return nil, "", err
		}
	}
	store, err := activitystore.NewSqlStore(ctx, dataDir, key)
	return store, key, err
}

// InitPermissionsManager returns the default permissions manager.
func InitPermissionsManager(store store.Store, metric metric.Meter) permissions.Manager {
	return permissions.NewManager(store)
}

// Metrics embeds the application metrics exposed by the integrations module.
type Metrics struct {
	telemetry.AppMetrics
}

// InitIntegrationMetrics wraps the application metrics without adding
// integration-specific meters.
func InitIntegrationMetrics(ctx context.Context, metrics telemetry.AppMetrics) (*Metrics, error) {
	return &Metrics{
		AppMetrics: metrics,
	}, nil
}

// IsValidChildAccount reports whether the account is a valid MSP child
// account. MSP features are not part of this fork, so it is always false.
func IsValidChildAccount(_ context.Context, _, _, _ string) bool {
	return false
}
