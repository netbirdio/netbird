package http

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

// EventsHandler HTTP handler
type EventsHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewEventsHandler creates a new EventsHandler HTTP handler
func NewEventsHandler(accountManager server.AccountManager, authCfg AuthCfg) *EventsHandler {
	return &EventsHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllEvents list of the given account
func (h *EventsHandler) GetAllEvents(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	accountEvents, err := h.accountManager.GetEvents(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	events := make([]*api.Event, 0)
	for _, e := range accountEvents {
		events = append(events, toEventResponse(e))
	}

	util.WriteJSONObject(w, events)
}

func toEventResponse(event *activity.Event) *api.Event {
	meta := make(map[string]string)
	if event.Meta != nil {
		for s, a := range event.Meta {
			meta[s] = fmt.Sprintf("%v", a)
		}
	}
	return &api.Event{
		Id:           fmt.Sprint(event.ID),
		InitiatorId:  event.InitiatorID,
		Activity:     event.Activity.Message(),
		ActivityCode: api.EventActivityCode(event.Activity.StringCode()),
		TargetId:     event.TargetID,
		Timestamp:    event.Timestamp,
		Meta:         meta,
	}
}
