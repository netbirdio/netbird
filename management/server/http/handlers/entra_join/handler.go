// Package entra_join hosts the device-side enrolment endpoints for the Entra
// device authentication feature. These endpoints live on the dedicated
// /join/entra path so they never mix with the normal Login/Sync gRPC flow or
// with the admin JSON API.
package entra_join

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	ed "github.com/netbirdio/netbird/management/server/integrations/entra_device"
)

// Handler serves the /join/entra/* routes.
type Handler struct {
	Manager *ed.Manager
}

// NewHandler constructs a handler using the given manager.
func NewHandler(m *ed.Manager) *Handler { return &Handler{Manager: m} }

// Register wires the routes onto router. Call this from the main HTTP handler
// initialiser. The route prefix is fixed as /join/entra to match the agreed
// UX (`--management-url https://.../join/entra`).
func (h *Handler) Register(router *mux.Router) {
	sub := router.PathPrefix("/join/entra").Subrouter()
	sub.HandleFunc("/challenge", h.challenge).Methods(http.MethodGet, http.MethodOptions)
	sub.HandleFunc("/enroll", h.enroll).Methods(http.MethodPost, http.MethodOptions)
}

// challenge issues a one-shot nonce for the device to sign.
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request) {
	resp, err := h.Manager.IssueChallenge(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// enroll runs the full Entra enrolment flow.
func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 512*1024))
	if err != nil {
		writeErrorMsg(w, http.StatusBadRequest, "io_error", "could not read request body")
		return
	}

	var req ed.EnrollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErrorMsg(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	// Server-derived real IP trumps what the client claims.
	if req.ConnectionIP == "" {
		req.ConnectionIP = realIP(r)
	}

	resp, err := h.Manager.Enroll(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError maps an Entra-integration error to the proper HTTP status + body.
func writeError(w http.ResponseWriter, err error) {
	if e, ok := ed.AsError(err); ok {
		writeJSON(w, e.HTTPStatus, errorPayload{
			Code:    string(e.Code),
			Message: e.Message,
		})
		return
	}
	writeJSON(w, http.StatusInternalServerError, errorPayload{
		Code:    "internal_error",
		Message: err.Error(),
	})
}

func writeErrorMsg(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorPayload{Code: code, Message: msg})
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// realIP returns the remote IP, preferring X-Forwarded-For if present (common
// behind an ingress controller).
func realIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	if rip := r.Header.Get("X-Real-IP"); rip != "" {
		return rip
	}
	return r.RemoteAddr
}
