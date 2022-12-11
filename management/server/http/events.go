package http

import (
	"fmt"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/event"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// Events HTTP handler
type Events struct {
	accountManager server.AccountManager
	authAudience   string
	jwtExtractor   jwtclaims.ClaimsExtractor
}

// NewEvents creates a new Events HTTP handler
func NewEvents(accountManager server.AccountManager, authAudience string) *Events {
	return &Events{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// GetEvents list of the given account
func (h *Events) GetEvents(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	_, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var groups []*api.Event

	util.WriteJSONObject(w, groups)
}

func toEventResponse(event *event.Event) *api.Event {
	return &api.Event{
		Id:            fmt.Sprint(event.ID),
		InitiatorId:   event.ModifierID,
		Operation:     event.Operation,
		OperationCode: int(event.OperationCode),
		TargetId:      event.TargetID,
		Timestamp:     event.Timestamp,
		Type:          event.Type,
	}
}
