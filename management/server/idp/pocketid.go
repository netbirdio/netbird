package idp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

type PocketIdManager struct {
	managementEndpoint string
	apiToken           string
	httpClient         ManagerHTTPClient
	credentials        ManagerCredentials
	helper             ManagerHelper
	appMetrics         telemetry.AppMetrics
}

type pocketIdCustomClaimDto struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type pocketIdUserDto struct {
	CustomClaims []pocketIdCustomClaimDto `json:"customClaims"`
	Disabled     bool                     `json:"disabled"`
	DisplayName  string                   `json:"displayName"`
	Email        string                   `json:"email"`
	FirstName    string                   `json:"firstName"`
	ID           string                   `json:"id"`
	IsAdmin      bool                     `json:"isAdmin"`
	LastName     string                   `json:"lastName"`
	LdapID       string                   `json:"ldapId"`
	Locale       string                   `json:"locale"`
	UserGroups   []pocketIdUserGroupDto   `json:"userGroups"`
	Username     string                   `json:"username"`
}

type pocketIdUserCreateDto struct {
	Disabled    bool   `json:"disabled,omitempty"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	FirstName   string `json:"firstName"`
	IsAdmin     bool   `json:"isAdmin,omitempty"`
	LastName    string `json:"lastName,omitempty"`
	Locale      string `json:"locale,omitempty"`
	Username    string `json:"username"`
}

func (p *pocketIdUserDto) userData() *UserData {
	return &UserData{
		Email:       p.Email,
		Name:        p.DisplayName,
		ID:          p.ID,
		AppMetadata: AppMetadata{},
	}
}

type pocketIdUserGroupDto struct {
	CreatedAt    string                   `json:"createdAt"`
	CustomClaims []pocketIdCustomClaimDto `json:"customClaims"`
	FriendlyName string                   `json:"friendlyName"`
	ID           string                   `json:"id"`
	LdapID       string                   `json:"ldapId"`
	Name         string                   `json:"name"`
}

func NewPocketIdManager(config PocketIdClientConfig, appMetrics telemetry.AppMetrics) (*PocketIdManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	if config.ManagementEndpoint == "" {
		return nil, fmt.Errorf("pocketId IdP configuration is incomplete, ManagementEndpoint is missing")
	}

	if config.APIToken == "" {
		return nil, fmt.Errorf("pocketId IdP configuration is incomplete, APIToken is missing")
	}

	credentials := &PocketIdCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &PocketIdManager{
		managementEndpoint: config.ManagementEndpoint,
		apiToken:           config.APIToken,
		httpClient:         httpClient,
		credentials:        credentials,
		helper:             helper,
		appMetrics:         appMetrics,
	}, nil
}

func (p *PocketIdManager) request(ctx context.Context, method, resource string, query *url.Values, body string) ([]byte, error) {
	var METHODS_WITH_BODY = []string{http.MethodPost, http.MethodPut}
	if !slices.Contains(METHODS_WITH_BODY, method) && body != "" {
		return nil, fmt.Errorf("Body provided to unsupported method: %s", method)
	}

	reqURL := fmt.Sprintf("%s/api/%s", p.managementEndpoint, resource)
	if query != nil {
		reqURL = fmt.Sprintf("%s?%s", reqURL, query.Encode())
	}
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequestWithContext(ctx, method, reqURL, strings.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, reqURL, nil)
	}
	if err != nil {
		return nil, err
	}

	req.Header.Add("X-API-KEY", p.apiToken)

	if body != "" {
		req.Header.Add("content-type", "application/json")
		req.Header.Add("content-length", fmt.Sprintf("%d", req.ContentLength))
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		if p.appMetrics != nil {
			p.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		if p.appMetrics != nil {
			p.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		// TODO: read and intepret PocketID Error
		return nil, fmt.Errorf("Unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

//func (p *PocketIdManager) post(ctx context.Context, resource string, body string) ([]byte, error) {
//	reqURL := fmt.Sprintf("%s/api/%s", p.managementEndpoint, resource)
//	req, err := http.NewRequest(http.MethodPost, reqURL, strings.NewReader(body))
//	if err != nil {
//		return nil, err
//	}
//	req.Header.Add("X-API-KEY", p.apiToken)
//	req.Header.Add("content-type", "application/json")
//	req.Header.Add("content-length", fmt.Sprintf("%d", len(body)))
//
//	resp, err := p.httpClient.Do(req)
//	if err != nil {
//		if p.appMetrics != nil {
//			p.appMetrics.IDPMetrics().CountRequestError()
//		}
//
//		return nil, err
//	}
//	defer resp.Body.Close()
//
//	if resp.StatusCode != 200 && resp.StatusCode != 201 {
//		if p.appMetrics != nil {
//			p.appMetrics.IDPMetrics().CountRequestStatusError()
//		}
//
//		zErr := readZitadelError(resp.Body)
//
//		return nil, fmt.Errorf("unable to post %s, statusCode %d, zitadel: %w", reqURL, resp.StatusCode, zErr)
//	}
//
//	return io.ReadAll(resp.Body)
//}

//
//func (p *PocketIdManager) get(ctx context.Context, resource string, q url.Values) ([]byte, error) {
//	reqURL := fmt.Sprintf("%s/api/%s?%s", p.managementEndpoint, resource, q.Encode())
//	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
//	if err != nil {
//		return nil, err
//	}
//	req.Header.Add("X-API-KEY", p.apiToken)
//	req.Header.Add("content-type", "application/json")
//
//	resp, err := p.httpClient.Do(req)
//	if err != nil {
//		if p.appMetrics != nil {
//			p.appMetrics.IDPMetrics().CountRequestError()
//		}
//
//		return nil, err
//	}
//	defer resp.Body.Close()
//
//	if resp.StatusCode != http.StatusOK {
//		if p.appMetrics != nil {
//			p.appMetrics.IDPMetrics().CountRequestStatusError()
//		}
//
//		zErr := readZitadelError(resp.Body)
//
//		return nil, fmt.Errorf("unable to get %s, statusCode %d, zitadel: %w", reqURL, resp.StatusCode, zErr)
//	}
//
//	return io.ReadAll(resp.Body)
//}
//
//func (p *PocketIdManager) put(ctx context.Context, resource string, body string) ([]byte, error) {
//	reqURL := fmt.Sprintf("%s/api/%s", p.managementEndpoint, resource)
//	req, err := http.NewRequest(http.MethodPut, reqURL, strings.NewReader(body))
//	if err != nil {
//		return nil, err
//	}
//	req.Header.Add("X-API-KEY", p.apiToken)
//	req.Header.Add("content-type", "application/json")
//	req.Header.Add("content-length", fmt.Sprintf("%d", len(body)))
//
//}

//func mapAppMetadataToCustomClaims(appMetadata AppMetadata) []pocketIdCustomClaimDto {
//	return []pocketIdCustomClaimDto{
//		{
//			Key:   "wt_account_id",
//			Value: appMetadata.WTAccountID,
//		},
//		{
//			Key:   "wt_pending_invite",
//			Value: strconv.FormatBool(*appMetadata.WTPendingInvite),
//		},
//		{
//			Key:   "wt_invited_by_email",
//			Value: appMetadata.WTInvitedBy,
//		},
//	}
//}
//
//func mapCustomClaimsToAppMetadata(customClaims []pocketIdCustomClaimDto) AppMetadata {
//	appMetadata := AppMetadata{}
//	for _, claim := range customClaims {
//		switch claim.Key {
//		case "wt_account_id":
//			appMetadata.WTAccountID = claim.Value
//		case "wt_pending_invite":
//			pendingInvite, _ := strconv.ParseBool(claim.Value)
//			appMetadata.WTPendingInvite = &pendingInvite
//		case "wt_invited_by_email":
//			appMetadata.WTInvitedBy = claim.Value
//		}
//	}
//
//	return appMetadata
//}

func (p *PocketIdManager) UpdateUserAppMetadata(_ context.Context, _ string, _ AppMetadata) error {
	return nil
}

func (p *PocketIdManager) GetUserDataByID(ctx context.Context, userId string, appMetadata AppMetadata) (*UserData, error) {
	body, err := p.request(ctx, http.MethodGet, "users/"+userId, nil, "")
	if err != nil {
		return nil, err
	}

	if p.appMetrics != nil {
		p.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	var user pocketIdUserDto
	err = p.helper.Unmarshal(body, &user)
	if err != nil {
		return nil, err
	}
	return user.userData(), nil
}

func (p *PocketIdManager) GetAccount(ctx context.Context, accountId string) ([]*UserData, error) {
	params := url.Values{
		// This value a
		"pagination[limit]": []string{"100"},
	}
	body, err := p.request(ctx, http.MethodGet, "users", &params, "")
	if err != nil {
		return nil, err
	}

	if p.appMetrics != nil {
		p.appMetrics.IDPMetrics().CountGetAccount()
	}

	var profiles struct{ data []pocketIdUserDto }
	err = p.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	for _, profile := range profiles.data {
		userData := profile.userData()
		userData.AppMetadata.WTAccountID = accountId

		users = append(users, userData)
	}
	return users, nil
}

func (p *PocketIdManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	params := url.Values{
		// This value a
		"pagination[limit]": []string{"100"},
	}
	body, err := p.request(ctx, http.MethodGet, "users", &params, "")
	if err != nil {
		return nil, err
	}

	if p.appMetrics != nil {
		p.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	var profiles struct{ data []pocketIdUserDto }
	err = p.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	for _, profile := range profiles.data {
		userData := profile.userData()
		indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], userData)
	}

	return indexedUsers, nil
}

func (p *PocketIdManager) CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error) {
	firstLast := strings.Split(name, " ")

	createUser := pocketIdUserCreateDto{
		Disabled:    false,
		DisplayName: name,
		Email:       email,
		FirstName:   firstLast[0],
		LastName:    firstLast[1],
		Username:    firstLast[0] + "." + firstLast[1],
	}
	payload, err := p.helper.Marshal(createUser)
	if err != nil {
		return nil, err
	}

	body, err := p.request(ctx, http.MethodPost, "users", nil, string(payload))
	if err != nil {
		return nil, err
	}
	var newUser pocketIdUserDto
	err = p.helper.Unmarshal(body, &newUser)
	if err != nil {
		return nil, err
	}

	if p.appMetrics != nil {
		p.appMetrics.IDPMetrics().CountCreateUser()
	}
	var pending bool = true
	ret := &UserData{
		Email: email,
		Name:  name,
		ID:    newUser.ID,
		AppMetadata: AppMetadata{
			WTAccountID:     accountID,
			WTPendingInvite: &pending,
			WTInvitedBy:     invitedByEmail,
		},
	}
	return ret, nil
}

func (p *PocketIdManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	params := url.Values{
		// This value a
		"search": []string{email},
	}
	body, err := p.request(ctx, http.MethodGet, "users", &params, "")
	if err != nil {
		return nil, err
	}

	if p.appMetrics != nil {
		p.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	var profiles struct{ data []pocketIdUserDto }
	err = p.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	for _, profile := range profiles.data {
		users = append(users, profile.userData())
	}
	return users, nil
}

func (p *PocketIdManager) InviteUserByID(ctx context.Context, userID string) error {
	_, err := p.request(ctx, http.MethodPut, "users/"+userID+"/one-time-access-email", nil, "")
	if err != nil {
		return err
	}
	return nil
}

func (p *PocketIdManager) DeleteUser(ctx context.Context, userID string) error {
	_, err := p.request(ctx, http.MethodDelete, "users/"+userID, nil, "")
	if err != nil {
		return err
	}

	if p.appMetrics != nil {
		p.appMetrics.IDPMetrics().CountDeleteUser()
	}

	return nil
}

var _ Manager = (*PocketIdManager)(nil)

type PocketIdClientConfig struct {
	APIToken           string
	ManagementEndpoint string
}

type PocketIdCredentials struct {
	clientConfig PocketIdClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	appMetrics   telemetry.AppMetrics
}

var _ ManagerCredentials = (*PocketIdCredentials)(nil)

func (p PocketIdCredentials) Authenticate(_ context.Context) (JWTToken, error) {
	return JWTToken{}, nil
}
