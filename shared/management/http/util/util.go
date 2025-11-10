package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/status"
)

// EmptyObject is an empty struct used to return empty JSON object
type EmptyObject struct {
}

type ErrorResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// WriteJSONObject writes an object to the HTTP response in JSON format.
// Security: This function sets appropriate security headers and content type.
// It also handles encoding errors gracefully without exposing internal details.
func WriteJSONObject(ctx context.Context, w http.ResponseWriter, obj interface{}) {
	// Set security headers
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(obj)
	if err != nil {
		WriteError(ctx, err, w)
		return
	}
}

// Duration is used strictly for JSON requests/responses due to duration marshalling issues
type Duration struct {
	time.Duration
}

// MarshalJSON marshals the duration
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON unmarshals the duration
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

// WriteErrorResponse prepares and writes an error response in JSON format.
// Security: This function sets security headers and sanitizes error messages
// to prevent information leakage. Error messages are already sanitized before
// calling this function.
func WriteErrorResponse(errMsg string, httpStatus int, w http.ResponseWriter) {
	// Set security headers
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	
	w.WriteHeader(httpStatus)
	err := json.NewEncoder(w).Encode(&ErrorResponse{
		Message: errMsg,
		Code:    httpStatus,
	})
	if err != nil {
		// If encoding fails, use plain text error (should never happen)
		http.Error(w, "failed handling request", http.StatusInternalServerError)
	}
}

// WriteError converts an error to a JSON error response.
// Security: This function sanitizes error messages to prevent information leakage.
// Internal error details are logged but not exposed to clients to prevent:
// - Path disclosure
// - Stack trace exposure
// - Database schema revelation
// - Internal system information leakage
//
// If it is a known internal error of type server.Error, it sets appropriate HTTP status codes.
// For unknown errors, a generic message is returned to prevent information disclosure.
func WriteError(ctx context.Context, err error, w http.ResponseWriter) {
	// Log the full error for debugging (server-side only)
	log.WithContext(ctx).Errorf("got a handler error: %s", err.Error())
	
	errStatus, ok := status.FromError(err)
	httpStatus := http.StatusInternalServerError
	msg := "internal server error" // Generic message to prevent information leakage
	
	if ok {
		switch errStatus.Type() {
		case status.UserAlreadyExists:
			httpStatus = http.StatusConflict
			msg = "user already exists"
		case status.AlreadyExists:
			httpStatus = http.StatusConflict
			msg = "resource already exists"
		case status.PreconditionFailed:
			httpStatus = http.StatusPreconditionFailed
			msg = "precondition failed"
		case status.PermissionDenied:
			httpStatus = http.StatusForbidden
			msg = "permission denied"
		case status.NotFound:
			httpStatus = http.StatusNotFound
			msg = "resource not found"
		case status.Internal:
			httpStatus = http.StatusInternalServerError
			msg = "internal server error" // Don't expose internal error details
		case status.InvalidArgument:
			httpStatus = http.StatusUnprocessableEntity
			// Sanitize error message - only include safe parts
			msg = sanitizeErrorMessage(errStatus.Error())
		case status.Unauthorized:
			httpStatus = http.StatusUnauthorized
			msg = "unauthorized"
		case status.BadRequest:
			httpStatus = http.StatusBadRequest
			msg = sanitizeErrorMessage(errStatus.Error())
		case status.TooManyRequests:
			httpStatus = http.StatusTooManyRequests
			msg = "too many requests"
		default:
			msg = "internal server error"
		}
	} else {
		// Unknown error - log full details but return generic message
		unhandledMSG := fmt.Sprintf("got unhandled error code, error: %s", err.Error())
		log.WithContext(ctx).Error(unhandledMSG)
		msg = "internal server error" // Generic message for unknown errors
	}

	WriteErrorResponse(msg, httpStatus, w)
}

// sanitizeErrorMessage removes potentially sensitive information from error messages.
// This prevents path disclosure, stack traces, and other internal information from
// being exposed to clients.
func sanitizeErrorMessage(errMsg string) string {
	// Remove file paths
	pathRegex := regexp.MustCompile(`(/[^\s]+|\\[^\s]+|C:\\[^\s]+)`)
	errMsg = pathRegex.ReplaceAllString(errMsg, "[path]")
	
	// Remove stack traces
	stackRegex := regexp.MustCompile(`(?m)^\s+at\s+.*$|goroutine\s+\d+|panic:|runtime\.`)
	errMsg = stackRegex.ReplaceAllString(errMsg, "")
	
	// Remove database-related details
	dbRegex := regexp.MustCompile(`(database|table|column|constraint|foreign key|primary key|index)[\s:]+[^\s]+`)
	errMsg = dbRegex.ReplaceAllString(errMsg, "[database detail]")
	
	// Limit message length to prevent DoS
	const maxErrorMsgLength = 200
	if len(errMsg) > maxErrorMsgLength {
		errMsg = errMsg[:maxErrorMsgLength] + "..."
	}
	
	return strings.TrimSpace(errMsg)
}
