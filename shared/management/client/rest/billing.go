package rest

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// BillingAPI APIs for billing and invoices
type BillingAPI struct {
	c *Client
}

// GetUsage retrieves current usage statistics for the account
// See more: https://docs.netbird.io/api/resources/billing#get-current-usage
func (a *BillingAPI) GetUsage(ctx context.Context) (*api.UsageStats, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/billing/usage", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.UsageStats](resp)
	return &ret, err
}

// GetSubscription retrieves the current subscription details
// See more: https://docs.netbird.io/api/resources/billing#get-current-subscription
func (a *BillingAPI) GetSubscription(ctx context.Context) (*api.Subscription, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/billing/subscription", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Subscription](resp)
	return &ret, err
}

// GetInvoices retrieves the account's paid invoices
// See more: https://docs.netbird.io/api/resources/billing#list-all-invoices
func (a *BillingAPI) GetInvoices(ctx context.Context) ([]api.InvoiceResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/billing/invoices", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.InvoiceResponse](resp)
	return ret, err
}

// GetInvoicePDF retrieves the invoice PDF URL
// See more: https://docs.netbird.io/api/resources/billing#get-invoice-pdf
func (a *BillingAPI) GetInvoicePDF(ctx context.Context, invoiceID string) (*api.InvoicePDFResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/billing/invoices/"+invoiceID+"/pdf", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.InvoicePDFResponse](resp)
	return &ret, err
}

// GetInvoiceCSV retrieves the invoice CSV content
// See more: https://docs.netbird.io/api/resources/billing#get-invoice-csv
func (a *BillingAPI) GetInvoiceCSV(ctx context.Context, invoiceID string) (string, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/billing/invoices/"+invoiceID+"/csv", nil, nil)
	if err != nil {
		return "", err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[string](resp)
	return ret, err
}
