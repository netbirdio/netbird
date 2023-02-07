package http

import (
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	log "github.com/sirupsen/logrus"
)

// Events HTTP handler
type Events struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewEvents creates a new Events HTTP handler
func NewEvents(accountManager server.AccountManager, authCfg AuthCfg) *Events {
	return &Events{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetEvents list of the given account
func (h *Events) GetEvents(w http.ResponseWriter, r *http.Request) {
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
