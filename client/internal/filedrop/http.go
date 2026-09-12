package filedrop

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// httpTransport adapts the receiver to plain HTTP/1.1 over the tunnel. It only
// parses requests, maps domain errors to status codes, and encodes responses.
type httpTransport struct {
	recv *receiver
}

func (t *httpTransport) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(pathOffers, t.handleOffers)
	mux.HandleFunc(pathOffersSlash, t.handleOffer)
	return mux
}

func (t *httpTransport) handleOffers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	sender, ok := t.identify(w, r)
	if !ok {
		return
	}

	var req OfferRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOfferBodySize)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed offer")
		return
	}

	offer, err := t.recv.submitOffer(sender, req)
	if err != nil {
		writeDomainError(w, err)
		return
	}

	status := http.StatusAccepted
	if offer.Decision == DecisionAccepted {
		status = http.StatusCreated
	}
	writeJSON(w, status, OfferResponse{ID: offer.ID, Decision: offer.Decision})
}

func (t *httpTransport) handleOffer(w http.ResponseWriter, r *http.Request) {
	sender, ok := t.identify(w, r)
	if !ok {
		return
	}

	id, index, hasIndex, err := parseOfferPath(r.URL.Path)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown path")
		return
	}

	if !hasIndex {
		switch r.Method {
		case http.MethodGet:
			t.handleOfferStatus(w, r, sender, id)
		case http.MethodDelete:
			t.handleOfferCancel(w, sender, id)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	switch r.Method {
	case http.MethodPut:
		t.handleUpload(w, r, sender, id, index)
	case http.MethodHead:
		t.handleUploadProbe(w, sender, id, index)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (t *httpTransport) handleOfferStatus(w http.ResponseWriter, r *http.Request, sender senderIdentity, id OfferID) {
	offer, err := t.recv.awaitDecision(r.Context(), sender, id)
	if err != nil {
		if errors.Is(err, ErrOfferNotFound) {
			writeDomainError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, OfferResponse{ID: offer.ID, Decision: offer.Decision})
}

func (t *httpTransport) handleOfferCancel(w http.ResponseWriter, sender senderIdentity, id OfferID) {
	if err := t.recv.withdraw(sender, id); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (t *httpTransport) handleUploadProbe(w http.ResponseWriter, sender senderIdentity, id OfferID, index int) {
	received, err := t.recv.receivedBytes(sender, id, index)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	w.Header().Set(HeaderReceivedBytes, strconv.FormatInt(received, 10))
	w.WriteHeader(http.StatusOK)
}

func (t *httpTransport) handleUpload(w http.ResponseWriter, r *http.Request, sender senderIdentity, id OfferID, index int) {
	offset, err := parseOffset(r.URL.Query().Get("offset"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := t.recv.upload(sender, id, index, offset, r.Body); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (t *httpTransport) identify(w http.ResponseWriter, r *http.Request) (senderIdentity, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		writeError(w, http.StatusForbidden, "unknown sender")
		return senderIdentity{}, false
	}

	sender, ok := t.recv.identify(addr)
	if !ok {
		writeError(w, http.StatusForbidden, "unknown sender")
		return senderIdentity{}, false
	}
	return sender, true
}

func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrRefused), errors.Is(err, ErrNotAccepted), errors.Is(err, ErrUnknownPeer):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrOfferNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrInvalidOffer):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrStorage):
		writeError(w, http.StatusInsufficientStorage, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func parseOfferPath(path string) (OfferID, int, bool, error) {
	rest := strings.TrimPrefix(path, pathOffersSlash)
	if rest == "" || rest == path {
		return "", 0, false, fmt.Errorf("not an offer path")
	}

	parts := strings.Split(rest, "/")
	if parts[0] == "" {
		return "", 0, false, fmt.Errorf("missing offer id")
	}
	id := OfferID(parts[0])

	switch len(parts) {
	case 1:
		return id, 0, false, nil
	case 3:
		if parts[1] != segmentFiles {
			return "", 0, false, fmt.Errorf("unknown sub-resource %q", parts[1])
		}
		index, err := strconv.Atoi(parts[2])
		if err != nil || index < 0 {
			return "", 0, false, fmt.Errorf("invalid file index")
		}
		return id, index, true, nil
	default:
		return "", 0, false, fmt.Errorf("unknown offer path")
	}
}

func parseOffset(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	offset, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("invalid offset")
	}
	return offset, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Debugf("write file drop response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
