package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/netbirdio/netbird/management/server/http/util"
)

// Client Management service HTTP REST API Client
type Client struct {
	managementURL string
	authHeader    string

	// Accounts NetBird account APIs
	// see more: https://docs.netbird.io/api/resources/accounts
	Accounts *AccountsAPI

	// Users NetBird users APIs
	// see more: https://docs.netbird.io/api/resources/users
	Users *UsersAPI

	// Tokens NetBird tokens APIs
	// see more: https://docs.netbird.io/api/resources/tokens
	Tokens *TokensAPI

	// Peers NetBird peers APIs
	// see more: https://docs.netbird.io/api/resources/peers
	Peers *PeersAPI

	// SetupKeys NetBird setup keys APIs
	// see more: https://docs.netbird.io/api/resources/setup-keys
	SetupKeys *SetupKeysAPI

	// Groups NetBird groups APIs
	// see more: https://docs.netbird.io/api/resources/groups
	Groups *GroupsAPI

	// Policies NetBird policies APIs
	// see more: https://docs.netbird.io/api/resources/policies
	Policies *PoliciesAPI

	// PostureChecks NetBird posture checks APIs
	// see more: https://docs.netbird.io/api/resources/posture-checks
	PostureChecks *PostureChecksAPI

	// Networks NetBird networks APIs
	// see more: https://docs.netbird.io/api/resources/networks
	Networks *NetworksAPI

	// Routes NetBird routes APIs
	// see more: https://docs.netbird.io/api/resources/routes
	Routes *RoutesAPI

	// DNS NetBird DNS APIs
	// see more: https://docs.netbird.io/api/resources/routes
	DNS *DNSAPI

	// GeoLocation NetBird Geo Location APIs
	// see more: https://docs.netbird.io/api/resources/geo-locations
	GeoLocation *GeoLocationAPI

	// Events NetBird Events APIs
	// see more: https://docs.netbird.io/api/resources/events
	Events *EventsAPI
}

// New initialize new Client instance using PAT token
func New(managementURL, token string) *Client {
	client := &Client{
		managementURL: managementURL,
		authHeader:    "Token " + token,
	}
	client.initialize()
	return client
}

// NewWithBearerToken initialize new Client instance using Bearer token type
func NewWithBearerToken(managementURL, token string) *Client {
	client := &Client{
		managementURL: managementURL,
		authHeader:    "Bearer " + token,
	}
	client.initialize()
	return client
}

func (c *Client) initialize() {
	c.Accounts = &AccountsAPI{c}
	c.Users = &UsersAPI{c}
	c.Tokens = &TokensAPI{c}
	c.Peers = &PeersAPI{c}
	c.SetupKeys = &SetupKeysAPI{c}
	c.Groups = &GroupsAPI{c}
	c.Policies = &PoliciesAPI{c}
	c.PostureChecks = &PostureChecksAPI{c}
	c.Networks = &NetworksAPI{c}
	c.Routes = &RoutesAPI{c}
	c.DNS = &DNSAPI{c}
	c.GeoLocation = &GeoLocationAPI{c}
	c.Events = &EventsAPI{c}
}

func (c *Client) NewRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.managementURL+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", c.authHeader)
	req.Header.Add("Accept", "application/json")
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 {
		parsedErr, pErr := parseResponse[util.ErrorResponse](resp)
		if pErr != nil {
			return nil, err
		}
		return nil, errors.New(parsedErr.Message)
	}

	return resp, nil
}

func parseResponse[T any](resp *http.Response) (T, error) {
	var ret T
	if resp.Body == nil {
		return ret, errors.New("No body")
	}
	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return ret, err
	}
	err = json.Unmarshal(bs, &ret)

	return ret, err
}
