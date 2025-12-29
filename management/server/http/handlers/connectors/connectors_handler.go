package connectors

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// API request/response types

// ConnectorResponse represents an IdP connector in API responses
type ConnectorResponse struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	State   string   `json:"state"`
	Issuer  string   `json:"issuer,omitempty"`
	Servers []string `json:"servers,omitempty"`
}

// OIDCConnectorRequest represents a request to create an OIDC connector
type OIDCConnectorRequest struct {
	Name              string   `json:"name"`
	Issuer            string   `json:"issuer"`
	ClientID          string   `json:"client_id"`
	ClientSecret      string   `json:"client_secret"`
	Scopes            []string `json:"scopes,omitempty"`
	IsAutoCreation    bool     `json:"is_auto_creation,omitempty"`
	IsAutoUpdate      bool     `json:"is_auto_update,omitempty"`
	IsCreationAllowed bool     `json:"is_creation_allowed,omitempty"`
	IsLinkingAllowed  bool     `json:"is_linking_allowed,omitempty"`
}

// LDAPConnectorRequest represents a request to create an LDAP connector
type LDAPConnectorRequest struct {
	Name              string              `json:"name"`
	Servers           []string            `json:"servers"`
	StartTLS          bool                `json:"start_tls,omitempty"`
	BaseDN            string              `json:"base_dn"`
	BindDN            string              `json:"bind_dn"`
	BindPassword      string              `json:"bind_password"`
	UserBase          string              `json:"user_base,omitempty"`
	UserObjectClass   []string            `json:"user_object_class,omitempty"`
	UserFilters       []string            `json:"user_filters,omitempty"`
	Timeout           string              `json:"timeout,omitempty"`
	Attributes        *LDAPAttributesRequest `json:"attributes,omitempty"`
	IsAutoCreation    bool                `json:"is_auto_creation,omitempty"`
	IsAutoUpdate      bool                `json:"is_auto_update,omitempty"`
	IsCreationAllowed bool                `json:"is_creation_allowed,omitempty"`
	IsLinkingAllowed  bool                `json:"is_linking_allowed,omitempty"`
}

// LDAPAttributesRequest maps LDAP attributes to user fields
type LDAPAttributesRequest struct {
	IDAttribute          string `json:"id_attribute,omitempty"`
	FirstNameAttribute   string `json:"first_name_attribute,omitempty"`
	LastNameAttribute    string `json:"last_name_attribute,omitempty"`
	DisplayNameAttribute string `json:"display_name_attribute,omitempty"`
	EmailAttribute       string `json:"email_attribute,omitempty"`
}

// SAMLConnectorRequest represents a request to create a SAML connector
type SAMLConnectorRequest struct {
	Name              string `json:"name"`
	MetadataXML       string `json:"metadata_xml,omitempty"`
	MetadataURL       string `json:"metadata_url,omitempty"`
	Binding           string `json:"binding,omitempty"`
	WithSignedRequest bool   `json:"with_signed_request,omitempty"`
	NameIDFormat      string `json:"name_id_format,omitempty"`
	IsAutoCreation    bool   `json:"is_auto_creation,omitempty"`
	IsAutoUpdate      bool   `json:"is_auto_update,omitempty"`
	IsCreationAllowed bool   `json:"is_creation_allowed,omitempty"`
	IsLinkingAllowed  bool   `json:"is_linking_allowed,omitempty"`
}

// handler handles HTTP requests for IdP connectors
type handler struct {
	accountManager account.Manager
}

// AddEndpoints registers the connector endpoints to the router
func AddEndpoints(accountManager account.Manager, router *mux.Router) {
	h := &handler{accountManager: accountManager}

	router.HandleFunc("/connectors", h.listConnectors).Methods("GET", "OPTIONS")
	router.HandleFunc("/connectors/{connectorId}", h.getConnector).Methods("GET", "OPTIONS")
	router.HandleFunc("/connectors/{connectorId}", h.deleteConnector).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/connectors/oidc", h.addOIDCConnector).Methods("POST", "OPTIONS")
	router.HandleFunc("/connectors/ldap", h.addLDAPConnector).Methods("POST", "OPTIONS")
	router.HandleFunc("/connectors/saml", h.addSAMLConnector).Methods("POST", "OPTIONS")
	router.HandleFunc("/connectors/{connectorId}/activate", h.activateConnector).Methods("POST", "OPTIONS")
	router.HandleFunc("/connectors/{connectorId}/deactivate", h.deleteConnector).Methods("POST", "OPTIONS")
}

// getConnectorManager retrieves the connector manager from the IdP manager
func (h *handler) getConnectorManager() (idp.ConnectorManager, error) {
	idpManager := h.accountManager.GetIdpManager()
	if idpManager == nil {
		return nil, status.Errorf(status.PreconditionFailed, "IdP manager is not configured")
	}

	connectorManager, ok := idpManager.(idp.ConnectorManager)
	if !ok {
		return nil, status.Errorf(status.PreconditionFailed, "IdP manager does not support connector management")
	}

	return connectorManager, nil
}

// listConnectors returns all configured IdP connectors
func (h *handler) listConnectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	// Only admins can manage connectors
	user, err := h.accountManager.GetUserByID(r.Context(), userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can manage IdP connectors"), w)
		return
	}

	connectorManager, err := h.getConnectorManager()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	connectors, err := connectorManager.ListConnectors(r.Context())
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to list connectors: %v", err), w)
		return
	}

	response := make([]*ConnectorResponse, 0, len(connectors))
	for _, c := range connectors {
		response = append(response, toConnectorResponse(c))
	}

	util.WriteJSONObject(r.Context(), w, response)
}

// getConnector returns a specific connector by ID
func (h *handler) getConnector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	user, err := h.accountManager.GetUserByID(r.Context(), userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can manage IdP connectors"), w)
		return
	}

	vars := mux.Vars(r)
	connectorID := vars["connectorId"]
	if connectorID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "connector ID is required"), w)
		return
	}

	connectorManager, err := h.getConnectorManager()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	connector, err := connectorManager.GetConnector(r.Context(), connectorID)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.NotFound, "connector not found: %v", err), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toConnectorResponse(connector))
}

// deleteConnector removes a connector
func (h *handler) deleteConnector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	user, err := h.accountManager.GetUserByID(r.Context(), userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can manage IdP connectors"), w)
		return
	}

	vars := mux.Vars(r)
	connectorID := vars["connectorId"]
	if connectorID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "connector ID is required"), w)
		return
	}

	connectorManager, err := h.getConnectorManager()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if err := connectorManager.DeleteConnector(r.Context(), connectorID); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to delete connector: %v", err), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// addOIDCConnector creates a new OIDC connector
func (h *handler) addOIDCConnector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	user, err := h.accountManager.GetUserByID(r.Context(), userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can manage IdP connectors"), w)
		return
	}

	var req OIDCConnectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("invalid request body", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "name is required"), w)
		return
	}
	if req.Issuer == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "issuer is required"), w)
		return
	}
	if req.ClientID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "client_id is required"), w)
		return
	}
	if req.ClientSecret == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "client_secret is required"), w)
		return
	}

	connectorManager, err := h.getConnectorManager()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	config := idp.OIDCConnectorConfig{
		Name:              req.Name,
		Issuer:            req.Issuer,
		ClientID:          req.ClientID,
		ClientSecret:      req.ClientSecret,
		Scopes:            req.Scopes,
		IsAutoCreation:    req.IsAutoCreation,
		IsAutoUpdate:      req.IsAutoUpdate,
		IsCreationAllowed: req.IsCreationAllowed,
		IsLinkingAllowed:  req.IsLinkingAllowed,
	}

	connector, err := connectorManager.AddOIDCConnector(r.Context(), config)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to add OIDC connector: %v", err), w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	util.WriteJSONObject(r.Context(), w, toConnectorResponse(connector))
}

// addLDAPConnector creates a new LDAP connector
func (h *handler) addLDAPConnector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	user, err := h.accountManager.GetUserByID(r.Context(), userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can manage IdP connectors"), w)
		return
	}

	var req LDAPConnectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("invalid request body", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "name is required"), w)
		return
	}
	if len(req.Servers) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "at least one server is required"), w)
		return
	}
	if req.BaseDN == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "base_dn is required"), w)
		return
	}
	if req.BindDN == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "bind_dn is required"), w)
		return
	}
	if req.BindPassword == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "bind_password is required"), w)
		return
	}

	connectorManager, err := h.getConnectorManager()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	config := idp.LDAPConnectorConfig{
		Name:              req.Name,
		Servers:          req.Servers,
		StartTLS:          req.StartTLS,
		BaseDN:            req.BaseDN,
		BindDN:            req.BindDN,
		BindPassword:      req.BindPassword,
		UserBase:          req.UserBase,
		UserObjectClass:   req.UserObjectClass,
		UserFilters:       req.UserFilters,
		Timeout:           req.Timeout,
		IsAutoCreation:    req.IsAutoCreation,
		IsAutoUpdate:      req.IsAutoUpdate,
		IsCreationAllowed: req.IsCreationAllowed,
		IsLinkingAllowed:  req.IsLinkingAllowed,
	}

	if req.Attributes != nil {
		config.Attributes = idp.LDAPAttributes{
			IDAttribute:          req.Attributes.IDAttribute,
			FirstNameAttribute:   req.Attributes.FirstNameAttribute,
			LastNameAttribute:    req.Attributes.LastNameAttribute,
			DisplayNameAttribute: req.Attributes.DisplayNameAttribute,
			EmailAttribute:       req.Attributes.EmailAttribute,
		}
	}

	connector, err := connectorManager.AddLDAPConnector(r.Context(), config)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to add LDAP connector: %v", err), w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	util.WriteJSONObject(r.Context(), w, toConnectorResponse(connector))
}

// addSAMLConnector creates a new SAML connector
func (h *handler) addSAMLConnector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	user, err := h.accountManager.GetUserByID(r.Context(), userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can manage IdP connectors"), w)
		return
	}

	var req SAMLConnectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("invalid request body", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "name is required"), w)
		return
	}
	if req.MetadataXML == "" && req.MetadataURL == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "either metadata_xml or metadata_url is required"), w)
		return
	}

	connectorManager, err := h.getConnectorManager()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	config := idp.SAMLConnectorConfig{
		Name:              req.Name,
		MetadataXML:       req.MetadataXML,
		MetadataURL:       req.MetadataURL,
		Binding:           req.Binding,
		WithSignedRequest: req.WithSignedRequest,
		NameIDFormat:      req.NameIDFormat,
		IsAutoCreation:    req.IsAutoCreation,
		IsAutoUpdate:      req.IsAutoUpdate,
		IsCreationAllowed: req.IsCreationAllowed,
		IsLinkingAllowed:  req.IsLinkingAllowed,
	}

	connector, err := connectorManager.AddSAMLConnector(r.Context(), config)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to add SAML connector: %v", err), w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	util.WriteJSONObject(r.Context(), w, toConnectorResponse(connector))
}

// activateConnector adds the connector to the login policy
func (h *handler) activateConnector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	user, err := h.accountManager.GetUserByID(r.Context(), userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can manage IdP connectors"), w)
		return
	}

	vars := mux.Vars(r)
	connectorID := vars["connectorId"]
	if connectorID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "connector ID is required"), w)
		return
	}

	connectorManager, err := h.getConnectorManager()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if err := connectorManager.ActivateConnector(r.Context(), connectorID); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to activate connector: %v", err), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// deactivateConnector removes the connector from the login policy
func (h *handler) deactivateConnector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	user, err := h.accountManager.GetUserByID(r.Context(), userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can manage IdP connectors"), w)
		return
	}

	vars := mux.Vars(r)
	connectorID := vars["connectorId"]
	if connectorID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "connector ID is required"), w)
		return
	}

	connectorManager, err := h.getConnectorManager()
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if err := connectorManager.DeactivateConnector(r.Context(), connectorID); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to deactivate connector: %v", err), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// toConnectorResponse converts an idp.Connector to a ConnectorResponse
func toConnectorResponse(c *idp.Connector) *ConnectorResponse {
	return &ConnectorResponse{
		ID:      c.ID,
		Name:    c.Name,
		Type:    string(c.Type),
		State:   c.State,
		Issuer:  c.Issuer,
		Servers: c.Servers,
	}
}
