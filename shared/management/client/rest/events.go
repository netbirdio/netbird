package rest

import (
	"context"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// EventsAPI APIs for Events, do not use directly
type EventsAPI struct {
	c *Client
}

// NetworkTrafficOption options for ListNetworkTrafficEvents API
type NetworkTrafficOption func(query map[string]string)

func NetworkTrafficPage(page int) NetworkTrafficOption {
	return func(query map[string]string) {
		query["page"] = fmt.Sprintf("%d", page)
	}
}

func NetworkTrafficPageSize(pageSize int) NetworkTrafficOption {
	return func(query map[string]string) {
		query["page_size"] = fmt.Sprintf("%d", pageSize)
	}
}

func NetworkTrafficUserID(userID string) NetworkTrafficOption {
	return func(query map[string]string) {
		query["user_id"] = userID
	}
}

func NetworkTrafficReporterID(reporterID string) NetworkTrafficOption {
	return func(query map[string]string) {
		query["reporter_id"] = reporterID
	}
}

func NetworkTrafficProtocol(protocol int) NetworkTrafficOption {
	return func(query map[string]string) {
		query["protocol"] = fmt.Sprintf("%d", protocol)
	}
}

func NetworkTrafficType(t api.GetApiEventsNetworkTrafficParamsType) NetworkTrafficOption {
	return func(query map[string]string) {
		query["type"] = string(t)
	}
}

func NetworkTrafficConnectionType(ct api.GetApiEventsNetworkTrafficParamsConnectionType) NetworkTrafficOption {
	return func(query map[string]string) {
		query["connection_type"] = string(ct)
	}
}

func NetworkTrafficDirection(d api.GetApiEventsNetworkTrafficParamsDirection) NetworkTrafficOption {
	return func(query map[string]string) {
		query["direction"] = string(d)
	}
}

func NetworkTrafficSearch(search string) NetworkTrafficOption {
	return func(query map[string]string) {
		query["search"] = search
	}
}

func NetworkTrafficStartDate(t time.Time) NetworkTrafficOption {
	return func(query map[string]string) {
		query["start_date"] = t.Format(time.RFC3339)
	}
}

func NetworkTrafficEndDate(t time.Time) NetworkTrafficOption {
	return func(query map[string]string) {
		query["end_date"] = t.Format(time.RFC3339)
	}
}

// ListAuditEvents list all audit events
// See more: https://docs.netbird.io/api/resources/events#list-all-audit-events
func (a *EventsAPI) ListAuditEvents(ctx context.Context) ([]api.Event, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/events/audit", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Event](resp)
	return ret, err
}

// ListNetworkTrafficEvents list network traffic events
// See more: https://docs.netbird.io/api/resources/events#list-network-traffic-events
func (a *EventsAPI) ListNetworkTrafficEvents(ctx context.Context, opts ...NetworkTrafficOption) (*api.NetworkTrafficEventsResponse, error) {
	query := make(map[string]string)
	for _, o := range opts {
		o(query)
	}
	resp, err := a.c.NewRequest(ctx, "GET", "/api/events/network-traffic", nil, query)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NetworkTrafficEventsResponse](resp)
	return &ret, err
}
