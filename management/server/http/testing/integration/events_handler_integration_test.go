//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func Test_Events_GetAll(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	for _, user := range users {
		t.Run(user.name+" - Get all events", func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/events.sql", nil, false)

			// First, perform a mutation to generate an event (create a group as admin)
			groupBody, err := json.Marshal(&api.GroupRequest{Name: "eventTestGroup"})
			if err != nil {
				t.Fatalf("Failed to marshal group request: %v", err)
			}
			createReq := testing_tools.BuildRequest(t, groupBody, http.MethodPost, "/api/groups", testing_tools.TestAdminId)
			createRecorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(createRecorder, createReq)
			assert.Equal(t, http.StatusOK, createRecorder.Code, "Failed to create group to generate event")

			// Now query events
			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/events", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.Event{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.GreaterOrEqual(t, len(got), 1, "Expected at least one event after creating a group")

			// Verify the group creation event exists
			found := false
			for _, event := range got {
				if event.ActivityCode == "group.add" {
					found = true
					assert.Equal(t, testing_tools.TestAdminId, event.InitiatorId)
					assert.Equal(t, "Group created", event.Activity)
					break
				}
			}
			assert.True(t, found, "Expected to find a group.add event")
		})
	}
}

func Test_Events_GetAll_Empty(t *testing.T) {
	apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/events.sql", nil, true)

	req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/events", testing_tools.TestAdminId)
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)

	content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, true)
	if !expectResponse {
		return
	}

	got := []api.Event{}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("Sent content is not in correct json format; %v", err)
	}

	assert.Equal(t, 0, len(got), "Expected empty events list when no mutations have been performed")

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("timeout waiting for peerShouldNotReceiveUpdate")
	}
}
