package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/management/internals/modules/credentials/recordwriter"
	"github.com/netbirdio/netbird/shared/management/status"
)

// recordWriterError is the typed error returned by CreateDomain when the
// auto-configure pre-step fails on a sentinel from the legoclient
// RecordWriter. It carries enough context for the API handler to render
// a structured JSON body the dashboard can react to without parsing
// strings.
//
// Manual-flow errors continue to flow through the existing
// shared/management/status + util.WriteError machinery — this type only
// covers the new auto-configure failure modes.
type recordWriterError struct {
	// ErrorCode is the canonical machine-readable identifier the dashboard
	// keys off (e.g., CREDENTIAL_INSUFFICIENT_SCOPE).
	ErrorCode string

	// Message is a human-readable string the dashboard may show as a
	// fallback. The dashboard is expected to localize / customize based
	// on ErrorCode and the surrounding context — never to parse Message
	// substrings.
	Message string

	// Provider is the DNS provider type the failure originated from.
	Provider string

	// FQDN is the record being written. Used by the dashboard to render
	// "A CNAME for *.app.example.com already exists..."-style messages.
	FQDN string

	// HTTPStatus is the HTTP status code to return.
	HTTPStatus int
}

func (e *recordWriterError) Error() string {
	return fmt.Sprintf("%s: %s (provider=%s fqdn=%s)", e.ErrorCode, e.Message, e.Provider, e.FQDN)
}

// recordWriterErrorBody is the JSON shape written to the HTTP response
// for record-writer errors. The dashboard reacts to error_code and
// renders the message inline.
type recordWriterErrorBody struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
	Provider  string `json:"provider,omitempty"`
	FQDN      string `json:"fqdn,omitempty"`
}

// mapRecordWriterError translates a legoclient sentinel into a typed
// *recordWriterError carrying the right HTTP status and error_code. The
// caller (handler) detects this type and writes a structured response;
// other errors fall through to util.WriteError.
func mapRecordWriterError(err error, provider, fqdn string) error {
	switch {
	case errors.Is(err, recordwriter.ErrInsufficientScope):
		return &recordWriterError{
			ErrorCode:  "CREDENTIAL_INSUFFICIENT_SCOPE",
			Message:    fmt.Sprintf("The %s credential cannot write CNAME records in the target zone. The credential authenticates correctly but lacks zone-write scope — broader than the cert-issuance scope. Create a credential with zone-write permissions or switch to Manual CNAME.", provider),
			Provider:   provider,
			FQDN:       fqdn,
			HTTPStatus: http.StatusUnprocessableEntity,
		}
	case errors.Is(err, recordwriter.ErrZoneNotFound):
		return &recordWriterError{
			ErrorCode:  "ZONE_NOT_FOUND",
			Message:    fmt.Sprintf("Could not find a zone for %s in your %s account. Confirm the domain is registered with this provider, or switch to Manual CNAME.", fqdn, provider),
			Provider:   provider,
			FQDN:       fqdn,
			HTTPStatus: http.StatusUnprocessableEntity,
		}
	case errors.Is(err, recordwriter.ErrRecordExists):
		return &recordWriterError{
			ErrorCode:  "RECORD_ALREADY_EXISTS",
			Message:    fmt.Sprintf("A CNAME for %s already exists pointing somewhere else. Remove the existing record or switch to Manual CNAME.", fqdn),
			Provider:   provider,
			FQDN:       fqdn,
			HTTPStatus: http.StatusConflict,
		}
	case errors.Is(err, recordwriter.ErrProviderRateLimited):
		return &recordWriterError{
			ErrorCode:  "PROVIDER_RATE_LIMITED",
			Message:    fmt.Sprintf("Your %s account is being rate-limited. Try again in a few minutes.", provider),
			Provider:   provider,
			FQDN:       fqdn,
			HTTPStatus: http.StatusTooManyRequests,
		}
	case errors.Is(err, recordwriter.ErrProviderUnavailable):
		return &recordWriterError{
			ErrorCode:  "PROVIDER_UNAVAILABLE",
			Message:    fmt.Sprintf("The %s API is currently unreachable.", provider),
			Provider:   provider,
			FQDN:       fqdn,
			HTTPStatus: http.StatusBadGateway,
		}
	}
	// Unknown error from the writer. Surface as Internal — the API
	// handler will fall through to util.WriteError and log it.
	return fmt.Errorf("%s auto-configure failed: %w", provider, err)
}

// mapCredentialResolveError converts a credential lookup failure into a
// status.Error. We don't issue a dedicated error_code for these because
// they happen before we know which provider was being targeted; the
// existing util.WriteError NotFound mapping is sufficient.
func mapCredentialResolveError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	return status.Errorf(status.NotFound, "credential not found or unavailable: %s", err.Error())
}

// AsRecordWriterError unwraps err to *recordWriterError if it is one.
// Used by the API handler to detect the structured-error path.
func AsRecordWriterError(err error) (*recordWriterError, bool) {
	var rwe *recordWriterError
	if errors.As(err, &rwe) {
		return rwe, true
	}
	return nil, false
}

// WriteRecordWriterError writes the structured JSON body and the
// configured HTTP status. Used by the API handler instead of
// util.WriteError for record-writer errors.
func WriteRecordWriterError(w http.ResponseWriter, e *recordWriterError) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(e.HTTPStatus)
	_ = json.NewEncoder(w).Encode(&recordWriterErrorBody{
		ErrorCode: e.ErrorCode,
		Message:   e.Message,
		Provider:  e.Provider,
		FQDN:      e.FQDN,
	})
}
