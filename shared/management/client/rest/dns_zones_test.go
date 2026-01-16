//go:build integration
// +build integration

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
	testZone = api.Zone{
		Id:                 "zone123",
		Name:               "test-zone",
		Domain:             "example.com",
		Enabled:            true,
		EnableSearchDomain: false,
		DistributionGroups: []string{"group1"},
	}

	testDNSRecord = api.DNSRecord{
		Id:      "record123",
		Name:    "www",
		Content: "192.168.1.1",
		Type:    api.DNSRecordTypeA,
		Ttl:     300,
	}
)

func TestDNSZone_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.Zone{testZone})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.ListZones(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testZone, ret[0])
	})
}

func TestDNSZone_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.ListZones(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestDNSZone_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testZone)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.GetZone(context.Background(), "zone123")
		require.NoError(t, err)
		assert.Equal(t, testZone, *ret)
	})
}

func TestDNSZone_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.GetZone(context.Background(), "zone123")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Empty(t, ret)
	})
}

func TestDNSZone_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiDnsZonesJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "test-zone", req.Name)
			assert.Equal(t, "example.com", req.Domain)
			retBytes, _ := json.Marshal(testZone)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		enabled := true
		ret, err := c.DNSZones.CreateZone(context.Background(), api.PostApiDnsZonesJSONRequestBody{
			Name:               "test-zone",
			Domain:             "example.com",
			Enabled:            &enabled,
			EnableSearchDomain: false,
			DistributionGroups: []string{"group1"},
		})
		require.NoError(t, err)
		assert.Equal(t, testZone, *ret)
	})
}

func TestDNSZone_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Invalid request", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.CreateZone(context.Background(), api.PostApiDnsZonesJSONRequestBody{
			Name:   "test-zone",
			Domain: "example.com",
		})
		assert.Error(t, err)
		assert.Equal(t, "Invalid request", err.Error())
		assert.Nil(t, ret)
	})
}

func TestDNSZone_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiDnsZonesZoneIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "updated-zone", req.Name)
			retBytes, _ := json.Marshal(testZone)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		enabled := true
		ret, err := c.DNSZones.UpdateZone(context.Background(), "zone123", api.PutApiDnsZonesZoneIdJSONRequestBody{
			Name:               "updated-zone",
			Domain:             "example.com",
			Enabled:            &enabled,
			EnableSearchDomain: false,
			DistributionGroups: []string{"group1"},
		})
		require.NoError(t, err)
		assert.Equal(t, testZone, *ret)
	})
}

func TestDNSZone_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Invalid request", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.UpdateZone(context.Background(), "zone123", api.PutApiDnsZonesZoneIdJSONRequestBody{
			Name:   "updated-zone",
			Domain: "example.com",
		})
		assert.Error(t, err)
		assert.Equal(t, "Invalid request", err.Error())
		assert.Nil(t, ret)
	})
}

func TestDNSZone_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.DNSZones.DeleteZone(context.Background(), "zone123")
		require.NoError(t, err)
	})
}

func TestDNSZone_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.DNSZones.DeleteZone(context.Background(), "zone123")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestDNSRecord_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.DNSRecord{testDNSRecord})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.ListRecords(context.Background(), "zone123")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testDNSRecord, ret[0])
	})
}

func TestDNSRecord_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Zone not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.ListRecords(context.Background(), "zone123")
		assert.Error(t, err)
		assert.Equal(t, "Zone not found", err.Error())
		assert.Empty(t, ret)
	})
}

func TestDNSRecord_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records/record123", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testDNSRecord)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.GetRecord(context.Background(), "zone123", "record123")
		require.NoError(t, err)
		assert.Equal(t, testDNSRecord, *ret)
	})
}

func TestDNSRecord_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records/record123", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.GetRecord(context.Background(), "zone123", "record123")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Empty(t, ret)
	})
}

func TestDNSRecord_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiDnsZonesZoneIdRecordsJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "www", req.Name)
			assert.Equal(t, "192.168.1.1", req.Content)
			assert.Equal(t, api.DNSRecordTypeA, req.Type)
			retBytes, _ := json.Marshal(testDNSRecord)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.CreateRecord(context.Background(), "zone123", api.PostApiDnsZonesZoneIdRecordsJSONRequestBody{
			Name:    "www",
			Content: "192.168.1.1",
			Type:    api.DNSRecordTypeA,
			Ttl:     300,
		})
		require.NoError(t, err)
		assert.Equal(t, testDNSRecord, *ret)
	})
}

func TestDNSRecord_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Invalid record", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.CreateRecord(context.Background(), "zone123", api.PostApiDnsZonesZoneIdRecordsJSONRequestBody{
			Name:    "www",
			Content: "192.168.1.1",
			Type:    api.DNSRecordTypeA,
			Ttl:     300,
		})
		assert.Error(t, err)
		assert.Equal(t, "Invalid record", err.Error())
		assert.Nil(t, ret)
	})
}

func TestDNSRecord_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records/record123", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "api", req.Name)
			assert.Equal(t, "192.168.1.2", req.Content)
			retBytes, _ := json.Marshal(testDNSRecord)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.UpdateRecord(context.Background(), "zone123", "record123", api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody{
			Name:    "api",
			Content: "192.168.1.2",
			Type:    api.DNSRecordTypeA,
			Ttl:     300,
		})
		require.NoError(t, err)
		assert.Equal(t, testDNSRecord, *ret)
	})
}

func TestDNSRecord_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records/record123", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Invalid record", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNSZones.UpdateRecord(context.Background(), "zone123", "record123", api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody{
			Name:    "api",
			Content: "192.168.1.2",
			Type:    api.DNSRecordTypeA,
			Ttl:     300,
		})
		assert.Error(t, err)
		assert.Equal(t, "Invalid record", err.Error())
		assert.Nil(t, ret)
	})
}

func TestDNSRecord_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records/record123", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.DNSZones.DeleteRecord(context.Background(), "zone123", "record123")
		require.NoError(t, err)
	})
}

func TestDNSRecord_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/zones/zone123/records/record123", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.DNSZones.DeleteRecord(context.Background(), "zone123", "record123")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestDNSZones_Integration(t *testing.T) {
	enabled := true
	zoneReq := api.ZoneRequest{
		Name:               "test-zone",
		Domain:             "test.example.com",
		Enabled:            &enabled,
		EnableSearchDomain: false,
		DistributionGroups: []string{"cs1tnh0hhcjnqoiuebeg"},
	}

	recordReq := api.DNSRecordRequest{
		Name:    "api.test.example.com",
		Content: "192.168.1.100",
		Type:    api.DNSRecordTypeA,
		Ttl:     300,
	}

	withBlackBoxServer(t, func(c *rest.Client) {
		zone, err := c.DNSZones.CreateZone(context.Background(), zoneReq)
		require.NoError(t, err)
		assert.Equal(t, "test-zone", zone.Name)
		assert.Equal(t, "test.example.com", zone.Domain)

		zones, err := c.DNSZones.ListZones(context.Background())
		require.NoError(t, err)
		assert.Equal(t, *zone, zones[0])

		getZone, err := c.DNSZones.GetZone(context.Background(), zone.Id)
		require.NoError(t, err)
		assert.Equal(t, *zone, *getZone)

		zoneReq.Name = "updated-zone"
		updatedZone, err := c.DNSZones.UpdateZone(context.Background(), zone.Id, zoneReq)
		require.NoError(t, err)
		assert.Equal(t, "updated-zone", updatedZone.Name)

		record, err := c.DNSZones.CreateRecord(context.Background(), zone.Id, recordReq)
		require.NoError(t, err)
		assert.Equal(t, "api.test.example.com", record.Name)
		assert.Equal(t, "192.168.1.100", record.Content)

		records, err := c.DNSZones.ListRecords(context.Background(), zone.Id)
		require.NoError(t, err)
		assert.Equal(t, *record, records[0])

		getRecord, err := c.DNSZones.GetRecord(context.Background(), zone.Id, record.Id)
		require.NoError(t, err)
		assert.Equal(t, *record, *getRecord)

		recordReq.Name = "www.test.example.com"
		updatedRecord, err := c.DNSZones.UpdateRecord(context.Background(), zone.Id, record.Id, recordReq)
		require.NoError(t, err)
		assert.Equal(t, "www.test.example.com", updatedRecord.Name)

		err = c.DNSZones.DeleteRecord(context.Background(), zone.Id, record.Id)
		require.NoError(t, err)

		records, err = c.DNSZones.ListRecords(context.Background(), zone.Id)
		require.NoError(t, err)
		assert.Len(t, records, 0)

		err = c.DNSZones.DeleteZone(context.Background(), zone.Id)
		require.NoError(t, err)

		zones, err = c.DNSZones.ListZones(context.Background())
		require.NoError(t, err)
		assert.Len(t, zones, 0)
	})
}
