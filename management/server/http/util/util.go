package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/status"
)

type ErrorResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// WriteJSONObject simply writes object to the HTTP response in JSON format
func WriteJSONObject(w http.ResponseWriter, obj interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(obj)
	if err != nil {
		WriteError(err, w)
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

// WriteErrorResponse prepares and writes an error response i nJSON
func WriteErrorResponse(errMsg string, httpStatus int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(httpStatus)
	err := json.NewEncoder(w).Encode(&ErrorResponse{
		Message: errMsg,
		Code:    httpStatus,
	})
	if err != nil {
		http.Error(w, "failed handling request", http.StatusInternalServerError)
	}
}

// WriteError converts an error to an JSON error response.
// If it is known internal error of type server.Error then it sets the messages from the error, a generic message otherwise
func WriteError(err error, w http.ResponseWriter) {
	log.Errorf("got a handler error: %s", err.Error())
	errStatus, ok := status.FromError(err)
	httpStatus := http.StatusInternalServerError
	msg := "internal server error"
	if ok {
		switch errStatus.Type() {
		case status.UserAlreadyExists:
			httpStatus = http.StatusConflict
		case status.AlreadyExists:
			httpStatus = http.StatusConflict
		case status.PreconditionFailed:
			httpStatus = http.StatusPreconditionFailed
		case status.PermissionDenied:
			httpStatus = http.StatusForbidden
		case status.NotFound:
			httpStatus = http.StatusNotFound
		case status.Internal:
			httpStatus = http.StatusInternalServerError
		case status.InvalidArgument:
			httpStatus = http.StatusUnprocessableEntity
		case status.Unauthorized:
			httpStatus = http.StatusUnauthorized
		case status.BadRequest:
			httpStatus = http.StatusBadRequest
		default:
		}
		msg = strings.ToLower(err.Error())
	} else {
		unhandledMSG := fmt.Sprintf("got unhandled error code, error: %s", err.Error())
		log.Error(unhandledMSG)
	}

	WriteErrorResponse(msg, httpStatus, w)
}
