package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/metric"
)

// IDPMetrics is common IdP metrics
type IDPMetrics struct {
	metaUpdateCounter          metric.Int64Counter
	getUserByEmailCounter      metric.Int64Counter
	getAllAccountsCounter      metric.Int64Counter
	createUserCounter          metric.Int64Counter
	deleteUserCounter          metric.Int64Counter
	getAccountCounter          metric.Int64Counter
	getUserByIDCounter         metric.Int64Counter
	authenticateRequestCounter metric.Int64Counter
	requestErrorCounter        metric.Int64Counter
	requestStatusErrorCounter  metric.Int64Counter
	ctx                        context.Context
}

// NewIDPMetrics creates new IDPMetrics struct and registers common
func NewIDPMetrics(ctx context.Context, meter metric.Meter) (*IDPMetrics, error) {
	metaUpdateCounter, err := meter.Int64Counter("management.idp.update.user.meta.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getUserByEmailCounter, err := meter.Int64Counter("management.idp.get.user.by.email.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getAllAccountsCounter, err := meter.Int64Counter("management.idp.get.accounts.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	createUserCounter, err := meter.Int64Counter("management.idp.create.user.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	deleteUserCounter, err := meter.Int64Counter("management.idp.delete.user.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getAccountCounter, err := meter.Int64Counter("management.idp.get.account.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getUserByIDCounter, err := meter.Int64Counter("management.idp.get.user.by.id.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	authenticateRequestCounter, err := meter.Int64Counter("management.idp.authenticate.request.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	requestErrorCounter, err := meter.Int64Counter("management.idp.request.error.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	requestStatusErrorCounter, err := meter.Int64Counter("management.idp.request.status.error.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	return &IDPMetrics{
		metaUpdateCounter:          metaUpdateCounter,
		getUserByEmailCounter:      getUserByEmailCounter,
		getAllAccountsCounter:      getAllAccountsCounter,
		createUserCounter:          createUserCounter,
		deleteUserCounter:          deleteUserCounter,
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

// CountDeleteUser ...
func (idpMetrics *IDPMetrics) CountDeleteUser() {
	idpMetrics.deleteUserCounter.Add(idpMetrics.ctx, 1)
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
