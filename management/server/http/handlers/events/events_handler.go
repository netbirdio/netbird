package events

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// handler HTTP handler
type handler struct {
	accountManager account.Manager
}

func AddEndpoints(accountManager account.Manager, router *mux.Router) {
	eventsHandler := newHandler(accountManager)
	router.HandleFunc("/events", eventsHandler.getAllEvents).Methods("GET", "OPTIONS")
	router.HandleFunc("/events/audit", eventsHandler.getAllEvents).Methods("GET", "OPTIONS")
}

// newHandler creates a new events handler
func newHandler(accountManager account.Manager) *handler {
	return &handler{accountManager: accountManager}
}

// getAllEvents list of the given account
func (h *handler) getAllEvents(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	accountEvents, err := h.accountManager.GetEvents(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	events := make([]*api.Event, len(accountEvents))
	for i, e := range accountEvents {
		events[i] = toEventResponse(e)
	}

	util.WriteJSONObject(r.Context(), w, events)
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
