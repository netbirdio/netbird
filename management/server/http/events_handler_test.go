package http

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

func initEventsTestData(account string, user *server.User, events ...*activity.Event) *EventsHandler {
	return &EventsHandler{
		accountManager: &mock_server.MockAccountManager{
			GetEventsFunc: func(accountID, userID string) ([]*activity.Event, error) {
				if accountID == account {
					return events, nil
				}
				return []*activity.Event{}, nil
			},
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
					Users: map[string]*server.User{
						user.Id: user,
					},
				}, user, nil
			},
			GetUsersFromAccountFunc: func(accountID, userID string) ([]*server.UserInfo, error) {
				return make([]*server.UserInfo, 0), nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "test_account",
				}
			}),
		),
	}
}

func generateEvents(accountID, userID string) []*activity.Event {
	ID := uint64(1)
	events := make([]*activity.Event, 0)
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.PeerAddedByUser,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "100.64.0.2",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.UserJoined,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.GroupCreated,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "group-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.SetupKeyUpdated,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "setup-key-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.SetupKeyUpdated,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "setup-key-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.SetupKeyRevoked,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "setup-key-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.SetupKeyOverused,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "setup-key-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.SetupKeyCreated,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "setup-key-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.RuleAdded,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "some-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.RuleRemoved,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "some-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.RuleUpdated,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "some-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	ID++
	events = append(events, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    activity.PeerAddedWithSetupKey,
		ID:          ID,
		InitiatorID: userID,
		TargetID:    "some-id",
		AccountID:   accountID,
		Meta:        map[string]any{"some": "meta"},
	})
	return events
}

func TestEvents_GetEvents(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:           "GetAllEvents OK",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/events/",
			expectedStatus: http.StatusOK,
		},
	}
	accountID := "test_account"
	adminUser := server.NewAdminUser("test_user")
	events := generateEvents(accountID, adminUser.Id)
	handler := initEventsTestData(accountID, adminUser, events...)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/events/", handler.GetAllEvents).Methods("GET")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
				return
			}

			if !tc.expectedBody {
				return
			}

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			var got []*api.Event
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Len(t, got, len(events))
			actual := map[string]*api.Event{}
			for _, event := range got {
				actual[event.Id] = event
			}

			for _, expected := range events {
				event, ok := actual[strconv.FormatUint(expected.ID, 10)]
				assert.True(t, ok)
				assert.Equal(t, expected.InitiatorID, event.InitiatorId)
				assert.Equal(t, expected.TargetID, event.TargetId)
				assert.Equal(t, expected.Activity.Message(), event.Activity)
				assert.Equal(t, expected.Activity.StringCode(), string(event.ActivityCode))
				assert.Equal(t, expected.Meta["some"], event.Meta["some"])
				assert.True(t, expected.Timestamp.Equal(event.Timestamp))
			}
		})
	}
}
