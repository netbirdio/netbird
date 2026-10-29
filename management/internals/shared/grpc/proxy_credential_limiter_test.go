package grpc

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCredentialVerificationRefillAndIsolation(t *testing.T) {
	now := time.Now()
	l := credentialVerificationLimiter{now: func() time.Time { return now }}
	key := credentialVerificationKey{accountID: "account", serviceID: "service"}
	for range credentialVerificationBurst {
		require.NoError(t, l.allow(key))
	}
	err := l.allow(key)
	require.Equal(t, codes.ResourceExhausted, status.Code(err), "the burst must be bounded")
	now = now.Add(3 * time.Second)
	err = l.allow(key)
	require.Equal(t, codes.ResourceExhausted, status.Code(err), "a partially refilled token must not permit a check")
	details := status.Convert(err).Details()
	require.Len(t, details, 1, "throttling must provide RetryInfo")
	retry, ok := details[0].(*errdetails.RetryInfo)
	require.True(t, ok, "retry details must use the standard message")
	assert.Equal(t, 3*time.Second, retry.RetryDelay.AsDuration(), "retry hint must reflect time until the next check")
	now = now.Add(3 * time.Second)
	require.NoError(t, l.allow(key))
	assert.Equal(t, codes.ResourceExhausted, status.Code(l.allow(key)), "only one check must refill every six seconds")
	require.NoError(t, l.allow(credentialVerificationKey{accountID: "other-account", serviceID: key.serviceID}))
	require.NoError(t, l.allow(credentialVerificationKey{accountID: key.accountID, serviceID: "other-service"}))
}

func TestCredentialVerificationCapacityAndExpiry(t *testing.T) {
	now := time.Now()
	l := credentialVerificationLimiter{now: func() time.Time { return now }}
	for i := range credentialVerificationMaxServices {
		require.NoError(t, l.allow(credentialVerificationKey{accountID: "account", serviceID: credentialServiceID(strconv.Itoa(i))}))
	}
	key := credentialVerificationKey{accountID: "account", serviceID: "new-service"}
	assert.Equal(t, codes.ResourceExhausted, status.Code(l.allow(key)), "capacity exhaustion must deny new checks")
	now = now.Add(credentialVerificationIdleTimeout)
	for range credentialVerificationBurst {
		require.NoError(t, l.allow(key))
	}
	assert.Equal(t, codes.ResourceExhausted, status.Code(l.allow(key)), "expiry must retain the normal burst bound")
}

func TestCredentialVerificationConcurrentChecksAndClose(t *testing.T) {
	var l credentialVerificationLimiter
	key := credentialVerificationKey{accountID: "account", serviceID: "service"}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if err := l.allow(key); err == nil {
				admitted.Add(1)
			} else {
				assert.Equal(t, codes.ResourceExhausted, status.Code(err), "excess checks must be throttled")
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, credentialVerificationBurst, admitted.Load(), "concurrent checks must share the burst")
	for range 10 {
		wg.Go(l.close)
		wg.Go(func() { assert.Error(t, l.allow(key)) })
	}
	wg.Wait()
	assert.Empty(t, l.services, "closing must release retained budgets")
	assert.Equal(t, codes.Unavailable, status.Code(l.allow(key)), "checks after close must fail closed")
}
