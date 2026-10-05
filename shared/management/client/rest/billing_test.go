//go:build integration

package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

var (
	testUsageStats = api.UsageStats{
		ActiveUsers: 15,
		TotalUsers:  20,
		ActivePeers: 10,
		TotalPeers:  25,
	}

	testSubscription = api.Subscription{
		Active:    true,
		PlanTier:  "basic",
		PriceId:   "price_1HhxOp",
		Currency:  "USD",
		Price:     1000,
		Provider:  "stripe",
		UpdatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	testInvoice = api.InvoiceResponse{
		Id:          "inv_123",
		PeriodStart: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
		Type:        "invoice",
	}

	testInvoicePDF = api.InvoicePDFResponse{
		Url: "https://example.com/invoice.pdf",
	}
)

func TestBilling_GetUsage_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/usage", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testUsageStats)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetUsage(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testUsageStats, *ret)
	})
}

func TestBilling_GetUsage_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/usage", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetUsage(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestBilling_GetSubscription_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/subscription", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testSubscription)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetSubscription(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testSubscription, *ret)
	})
}

func TestBilling_GetSubscription_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/subscription", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetSubscription(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestBilling_GetInvoices_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/invoices", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.InvoiceResponse{testInvoice})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetInvoices(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testInvoice, ret[0])
	})
}

func TestBilling_GetInvoices_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/invoices", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetInvoices(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestBilling_GetInvoicePDF_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/invoices/inv_123/pdf", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testInvoicePDF)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetInvoicePDF(context.Background(), "inv_123")
		require.NoError(t, err)
		assert.Equal(t, testInvoicePDF, *ret)
	})
}

func TestBilling_GetInvoicePDF_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/invoices/inv_123/pdf", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetInvoicePDF(context.Background(), "inv_123")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestBilling_GetInvoiceCSV_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/invoices/inv_123/csv", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal("col1,col2\nval1,val2")
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetInvoiceCSV(context.Background(), "inv_123")
		require.NoError(t, err)
		assert.Equal(t, "col1,col2\nval1,val2", ret)
	})
}

func TestBilling_GetInvoiceCSV_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/billing/invoices/inv_123/csv", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Billing.GetInvoiceCSV(context.Background(), "inv_123")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Empty(t, ret)
	})
}
