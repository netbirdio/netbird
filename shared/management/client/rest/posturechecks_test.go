//go:build integration

package rest_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

var (
	testPostureCheck = api.PostureCheck{
		Id:   "Test",
		Name: "wow",
	}
)

func TestPostureChecks_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.PostureCheck{testPostureCheck})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.PostureChecks.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testPostureCheck, ret[0])
	})
}

func TestPostureChecks_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.PostureChecks.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPostureChecks_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testPostureCheck)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.PostureChecks.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testPostureCheck, *ret)
	})
}

func TestPostureChecks_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.PostureChecks.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPostureChecks_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostureCheckUpdate
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testPostureCheck)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.PostureChecks.Create(context.Background(), api.PostureCheckUpdate{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testPostureCheck, *ret)
	})
}

func TestPostureChecks_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.PostureChecks.Create(context.Background(), api.PostureCheckUpdate{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPostureChecks_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostureCheckUpdate
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testPostureCheck)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.PostureChecks.Update(context.Background(), "Test", api.PostureCheckUpdate{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testPostureCheck, *ret)
	})
}

func TestPostureChecks_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.PostureChecks.Update(context.Background(), "Test", api.PostureCheckUpdate{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPostureChecks_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.PostureChecks.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestPostureChecks_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/posture-checks/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.PostureChecks.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestPostureChecks_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		check, err := c.PostureChecks.Create(context.Background(), api.PostureCheckUpdate{
			Name:        "Test",
			Description: "Testing",
			Checks: &api.Checks{
				OsVersionCheck: &api.OSVersionCheck{
					Windows: &api.MinKernelVersionCheck{
						MinKernelVersion: "0.0.0",
					},
				},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Test", check.Name)

		checks, err := c.PostureChecks.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, checks, 1)

		check, err = c.PostureChecks.Update(context.Background(), check.Id, api.PostureCheckUpdate{
			Name:        "Tests",
			Description: "Testings",
			Checks: &api.Checks{
				GeoLocationCheck: &api.GeoLocationCheck{
					Action: api.GeoLocationCheckActionAllow, Locations: []api.Location{
						{
							CityName:    ptr("Cairo"),
							CountryCode: "EG",
						},
					},
				},
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "Testings", *check.Description)

		check, err = c.PostureChecks.Get(context.Background(), check.Id)
		require.NoError(t, err)
		assert.Equal(t, "Tests", check.Name)

		err = c.PostureChecks.Delete(context.Background(), check.Id)
		require.NoError(t, err)
	})
}
