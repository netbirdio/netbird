package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/netbirdio/netbird/management/server/status"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

// WriteJSONObject simply writes object to the HTTP reponse in JSON format
func WriteJSONObject(w http.ResponseWriter, obj interface{}) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err := json.NewEncoder(w).Encode(obj)
	if err != nil {
		http.Error(w, "failed handling request", http.StatusInternalServerError)
		return
	}
}

// Duration is used strictly for JSON requests/responses due to duration marshalling issues
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

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

// WriteError converts an error to an JSON error response.
// If it is known internal error of type server.Error then it sets the messages from the error, a generic message otherwise
func WriteError(err error, w http.ResponseWriter) {
	errStatus, ok := status.FromError(err)
	httpStatus := http.StatusInternalServerError
	msg := "internal server error"
	if ok {
		switch errStatus.Type() {
		case status.UserAlreadyExists:
		case status.AlreadyExists:
		case status.PreconditionFailed:
			httpStatus = http.StatusPreconditionFailed
		case status.PermissionDenied:
			httpStatus = http.StatusForbidden
		case status.NotFound:
			httpStatus = http.StatusNotFound
		case status.Internal:
			httpStatus = http.StatusInternalServerError
		case status.InvalidArgument:
			httpStatus = http.StatusBadRequest
		default:
		}
		msg = err.Error()
	} else {
		unhandledMSG := fmt.Sprintf("got unhandled error code, error: %s", err.Error())
		log.Error(unhandledMSG)
	}

	type errorResponse struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	}

	w.WriteHeader(httpStatus)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err = json.NewEncoder(w).Encode(&errorResponse{
		Message: msg,
		Code:    httpStatus,
	})
	if err != nil {
		http.Error(w, "failed handling request", http.StatusInternalServerError)
	}
}
