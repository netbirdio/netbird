//go:build integration

package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

var (
	testEvent = api.Event{
		Activity:     "AccountCreate",
		ActivityCode: api.EventActivityCodeAccountCreate,
	}
)

func TestEvents_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Event{testEvent})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Events.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testEvent, ret[0])
	})
}

func TestEvents_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Events.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestEvents_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		// Do something that would trigger any event
		_, err := c.SetupKeys.Create(context.Background(), api.CreateSetupKeyRequest{
			Ephemeral: ptr(true),
			Name:      "TestSetupKey",
			Type:      "reusable",
		})
		require.NoError(t, err)

		events, err := c.Events.List(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, events)
	})
}
