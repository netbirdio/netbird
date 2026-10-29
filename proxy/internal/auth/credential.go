package auth

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
)

var errCredentialClientIP = errors.New("invalid client address")

type credentialLimitError struct {
	retryAfter time.Duration
}

func (e *credentialLimitError) Error() string {
	return "too many authentication attempts"
}

func credentialFormValue(r *http.Request, field string) string {
	if r.Method != http.MethodPost {
		return ""
	}
	return r.PostFormValue(field)
}

func (mw *Middleware) authenticateScheme(r *http.Request, config DomainConfig, scheme Scheme) (string, string, error) {
	method := scheme.Type()
	if (method != auth.MethodPIN && method != auth.MethodPassword) || !wasCredentialSubmitted(r, method) {
		return scheme.Authenticate(r)
	}
	ip := mw.resolveClientIP(r).Unmap()
	if !ip.IsValid() {
		return "", "", errCredentialClientIP
	}
	source, retry := mw.credentials.begin(credentialSourceKey{
		service: credentialServiceKey{accountID: config.AccountID, serviceID: config.ServiceID},
		ip:      ip,
	})
	if retry > 0 {
		return "", "", &credentialLimitError{retryAfter: retry}
	}
	token, prompt, err := scheme.Authenticate(r)
	outcome := credentialUnavailable
	if err == nil {
		outcome = credentialRejected
		if token != "" {
			outcome = credentialAccepted
		}
	}
	mw.credentials.finish(source, outcome)
	return token, prompt, err
}

func credentialRetryAfter(err error) time.Duration {
	var limitErr *credentialLimitError
	if errors.As(err, &limitErr) {
		return limitErr.retryAfter
	}
	s := status.Convert(err)
	if s.Code() != codes.ResourceExhausted {
		return 0
	}
	for _, detail := range s.Details() {
		if info, ok := detail.(*errdetails.RetryInfo); ok && info.RetryDelay != nil && info.RetryDelay.CheckValid() == nil {
			if delay := info.RetryDelay.AsDuration(); delay > 0 {
				return delay
			}
		}
	}
	return credentialCheckInterval
}

func (mw *Middleware) writeAuthenticationError(w http.ResponseWriter, r *http.Request, method auth.Method, err error) {
	if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(proxy.OriginAuth)
		cd.SetAuthMethod(method.String())
	}
	if retry := credentialRetryAfter(err); retry > 0 {
		// RFC 6585 section 4 forbids caching 429 responses.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(retry.Seconds())), 10))
		http.Error(w, "too many authentication attempts; try again later", http.StatusTooManyRequests)
		return
	}
	if errors.Is(err, errCredentialClientIP) {
		http.Error(w, "invalid client address", http.StatusBadRequest)
		return
	}
	mw.logger.WithField("scheme", method.String()).Warnf("authentication infrastructure error: %v", err)
	http.Error(w, "authentication service unavailable", http.StatusBadGateway)
}
