package telemetry

import (
	"context"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
)

// IDPMetrics is common IdP metrics
type IDPMetrics struct {
	metaUpdateCounter          syncint64.Counter
	getUserByEmailCounter      syncint64.Counter
	getAllAccountsCounter      syncint64.Counter
	createUserCounter          syncint64.Counter
	getAccountCounter          syncint64.Counter
	getUserByIDCounter         syncint64.Counter
	authenticateRequestCounter syncint64.Counter
	requestErrorCounter        syncint64.Counter
	requestStatusErrorCounter  syncint64.Counter
	ctx                        context.Context
}

// NewIDPMetrics creates new IDPMetrics struct and registers common
func NewIDPMetrics(ctx context.Context, meter metric.Meter) (*IDPMetrics, error) {
	metaUpdateCounter, err := meter.SyncInt64().Counter("management.idp.update.user.meta.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getUserByEmailCounter, err := meter.SyncInt64().Counter("management.idp.get.user.by.email.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getAllAccountsCounter, err := meter.SyncInt64().Counter("management.idp.get.accounts.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	createUserCounter, err := meter.SyncInt64().Counter("management.idp.create.user.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getAccountCounter, err := meter.SyncInt64().Counter("management.idp.get.account.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getUserByIDCounter, err := meter.SyncInt64().Counter("management.idp.get.user.by.id.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	authenticateRequestCounter, err := meter.SyncInt64().Counter("management.idp.authenticate.request.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	requestErrorCounter, err := meter.SyncInt64().Counter("management.idp.request.error.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	requestStatusErrorCounter, err := meter.SyncInt64().Counter("management.idp.request.status.error.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	return &IDPMetrics{
		metaUpdateCounter:          metaUpdateCounter,
		getUserByEmailCounter:      getUserByEmailCounter,
		getAllAccountsCounter:      getAllAccountsCounter,
		createUserCounter:          createUserCounter,
		getAccountCounter:          getAccountCounter,
		getUserByIDCounter:         getUserByIDCounter,
		authenticateRequestCounter: authenticateRequestCounter,
		requestErrorCounter:        requestErrorCounter,
		requestStatusErrorCounter:  requestStatusErrorCounter,
		ctx:                        ctx}, nil
}

// CountUpdateUserAppMetadata ...
func (idpMetrics *IDPMetrics) CountUpdateUserAppMetadata() {
	idpMetrics.metaUpdateCounter.Add(idpMetrics.ctx, 1)
}

// CountGetUserByEmail ...
func (idpMetrics *IDPMetrics) CountGetUserByEmail() {
	idpMetrics.getUserByEmailCounter.Add(idpMetrics.ctx, 1)
}

// CountCreateUser ...
func (idpMetrics *IDPMetrics) CountCreateUser() {
	idpMetrics.createUserCounter.Add(idpMetrics.ctx, 1)
}

// CountGetAllAccounts ...
func (idpMetrics *IDPMetrics) CountGetAllAccounts() {
	idpMetrics.getAllAccountsCounter.Add(idpMetrics.ctx, 1)
}

// CountGetAccount ...
func (idpMetrics *IDPMetrics) CountGetAccount() {
	idpMetrics.getAccountCounter.Add(idpMetrics.ctx, 1)
}

// CountGetUserDataByID ...
func (idpMetrics *IDPMetrics) CountGetUserDataByID() {
	idpMetrics.getUserByIDCounter.Add(idpMetrics.ctx, 1)
}

// CountAuthenticate ...
func (idpMetrics *IDPMetrics) CountAuthenticate() {
	idpMetrics.authenticateRequestCounter.Add(idpMetrics.ctx, 1)
}

// CountRequestError counts number of error that happened when doing http request (httpClient.Do)
func (idpMetrics *IDPMetrics) CountRequestError() {
	idpMetrics.requestErrorCounter.Add(idpMetrics.ctx, 1)
}

// CountRequestStatusError counts number of responses that came from IdP with non success status code
func (idpMetrics *IDPMetrics) CountRequestStatusError() {
	idpMetrics.requestStatusErrorCounter.Add(idpMetrics.ctx, 1)
}
