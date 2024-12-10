package events

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

// handler HTTP handler
type handler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func AddEndpoints(accountManager server.AccountManager, authCfg configs.AuthCfg, router *mux.Router) {
	eventsHandler := newHandler(accountManager, authCfg)
	router.HandleFunc("/events", eventsHandler.getAllEvents).Methods("GET", "OPTIONS")
}

// newHandler creates a new events handler
func newHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *handler {
	return &handler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// getAllEvents list of the given account
func (h *handler) getAllEvents(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	accountEvents, err := h.accountManager.GetEvents(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	events := make([]*api.Event, len(accountEvents))
	for i, e := range accountEvents {
		events[i] = toEventResponse(e)
	}

	err = h.fillEventsWithUserInfo(r.Context(), events, accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, events)
}

func (h *handler) fillEventsWithUserInfo(ctx context.Context, events []*api.Event, accountId, userId string) error {
	// build email, name maps based on users
	userInfos, err := h.accountManager.GetUsersFromAccount(ctx, accountId, userId)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get users from account: %s", err)
		return err
	}

	emails := make(map[string]string)
	names := make(map[string]string)
	for _, ui := range userInfos {
		emails[ui.ID] = ui.Email
		names[ui.ID] = ui.Name
	}

	var ok bool
	for _, event := range events {
		// fill initiator
		if event.InitiatorEmail == "" {
			event.InitiatorEmail, ok = emails[event.InitiatorId]
			if !ok {
				log.WithContext(ctx).Warnf("failed to resolve email for initiator: %s", event.InitiatorId)
			}
		}

		if event.InitiatorName == "" {
			// here to allowed to be empty because in the first release we did not store the name
			event.InitiatorName = names[event.InitiatorId]
		}

		// fill target meta
		email, ok := emails[event.TargetId]
		if !ok {
			continue
		}
		event.Meta["email"] = email

		username, ok := names[event.TargetId]
		if !ok {
			continue
		}
		event.Meta["username"] = username
	}
	return nil
}

func toEventResponse(event *activity.Event) *api.Event {
	meta := make(map[string]string)
	if event.Meta != nil {
		for s, a := range event.Meta {
			meta[s] = fmt.Sprintf("%v", a)
		}
	}
	e := &api.Event{
		Id:             fmt.Sprint(event.ID),
		InitiatorId:    event.InitiatorID,
		InitiatorName:  event.InitiatorName,
		InitiatorEmail: event.InitiatorEmail,
		Activity:       event.Activity.Message(),
		ActivityCode:   api.EventActivityCode(event.Activity.StringCode()),
		TargetId:       event.TargetID,
		Timestamp:      event.Timestamp,
		Meta:           meta,
	}
	return e
}
