package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Helper: find client details by clientId
func (m *KCClientManager) findKeycloakClientByClientID(ctx context.Context, clientId string) (*KeycloakClient, error) {
	token, err := m.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/admin/realms/%s/clients?clientId=%s", m.Endpoint, m.Realm, clientId)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("find client error: %s", resp.Status)
	}
	var clients []KeycloakClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("client not found by clientId: %s", clientId)
	}
	return &clients[0], nil
}

// Helper: get client secret from Keycloak API by client uuid
func (m *KCClientManager) getClientSecret(ctx context.Context, clientUuid string) (string, error) {
	token, err := m.getAdminToken(ctx)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/admin/realms/%s/clients/%s/client-secret", m.Endpoint, m.Realm, clientUuid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("get secret error: %s", resp.Status)
	}
	var secretResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return "", err
	}
	return secretResp.Value, nil
}

// ClientManager provides administration operations for OIDC OAuth2 clients.
type KCClientManager struct {
    Endpoint   string
    Realm      string
    HTTPClient *http.Client
    adminUser  string
    adminPass  string
    token      string
}

// NewClientManager creates a new ClientManager targeting the given admin API endpoint.
// If httpClient is nil, http.DefaultClient will be used.
func NewKCClientManager(endpoint string, httpClient interface{}) *KCClientManager {
    hc, _ := httpClient.(*http.Client)
    if hc == nil {
        hc = http.DefaultClient
    }
    realm := os.Getenv("KEYCLOAK_REALM")
    if realm == "" {
        realm = "maccs-demo"
    }
    adminUser := os.Getenv("KEYCLOAK_ADMIN_USER")
    if adminUser == "" {
        adminUser = "admin"
    }
    adminPass := os.Getenv("KEYCLOAK_ADMIN_PASSWORD")
    if adminPass == "" {
        adminPass = "admin"
    }
    return &KCClientManager{
        Endpoint:   strings.TrimRight(endpoint, "/"),
        Realm:      realm,
        HTTPClient: hc,
        adminUser:  adminUser,
        adminPass:  adminPass,
    }
}

// CreateClientRequest represents the JSON body for creating or updating an OAuth2 client.

// Keycloak client model for admin API
type KeycloakClient struct {
	ID                        string   `json:"id,omitempty"`
	ClientID                  string   `json:"clientId"`
	Name                      string   `json:"name,omitempty"`
	Secret                    string   `json:"secret,omitempty"`
	PublicClient              bool     `json:"publicClient"`
	RedirectURIs              []string `json:"redirectUris,omitempty"`
	ServiceAccountsEnabled    bool     `json:"serviceAccountsEnabled,omitempty"`
	AuthorizationServices     bool     `json:"authorizationServicesEnabled,omitempty"`
	StandardFlowEnabled       bool     `json:"standardFlowEnabled,omitempty"`
	ImplicitFlowEnabled       bool     `json:"implicitFlowEnabled,omitempty"`
	DirectAccessGrantsEnabled bool     `json:"directAccessGrantsEnabled,omitempty"`
	RootURL                   string   `json:"rootUrl,omitempty"`
	AdminURL                  string   `json:"adminUrl,omitempty"`
	BaseURL                   string   `json:"baseUrl,omitempty"`
	BearerOnly                bool     `json:"bearerOnly,omitempty"`
	Protocol                  string   `json:"protocol,omitempty"`
	Description               string   `json:"description,omitempty"`
	WebOrigins                []string `json:"webOrigins,omitempty"`
	SecretGenerated           bool     `json:"secretGenerated,omitempty"`
	Enabled                   bool     `json:"enabled"`
	FullScopeAllowed          bool     `json:"fullScopeAllowed"`
	DefaultClientScopes       []string `json:"defaultClientScopes,omitempty"`
	OptionalClientScopes      []string `json:"optionalClientScopes,omitempty"`
}


func (m *KCClientManager) getAdminToken(ctx context.Context) (string, error) {
    if m.token != "" {
        return m.token, nil
    }
    form := fmt.Sprintf("username=%s&password=%s&grant_type=password&client_id=admin-cli",
        m.adminUser, m.adminPass,
    )
    url := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", m.Endpoint)
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(form))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    resp, err := m.HTTPClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return "", fmt.Errorf("failed to get admin token: %s", resp.Status)
    }
    var adminResp struct {
        AccessToken string `json:"access_token"`
    }
    decoder := json.NewDecoder(resp.Body)
    if err := decoder.Decode(&adminResp); err != nil {
        return "", err
    }
    m.token = adminResp.AccessToken
    return adminResp.AccessToken, nil
}

// ---- CreateUserClient for Keycloak ----
func (m *KCClientManager) CreateUserClient(ctx context.Context, id string, redirectURIs, scopes []string) (*OAuth2Client, error) {
	token, err := m.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}
	kc := KeycloakClient{
		ID:                  id,
		Name:                      id,
		RedirectURIs:              redirectURIs,
		Enabled:                   true,
		Protocol:                  "openid-connect",
		PublicClient:              false,
		StandardFlowEnabled:       true,
		DirectAccessGrantsEnabled: false,
	}
	data, err := json.Marshal(kc)
	if err != nil {
		return nil, fmt.Errorf("marshal KeycloakClient: %w", err)
	}
	url := fmt.Sprintf("%s/admin/realms/%s/clients", m.Endpoint, m.Realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client create: %w", err)
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return nil, fmt.Errorf("keycloak client create: code=%d, body=%s", resp.StatusCode, b)
	}
	// Fetch client details by clientId to return info (including generated secret)
	kcc, err := m.findKeycloakClientByClientID(ctx, id)
	if err != nil {
		return nil, err
	}
	clientSecret, err := m.getClientSecret(ctx, kcc.ID)
	if err != nil {
		return nil, err
	}
   return &OAuth2Client{
       ID:           id,
       Secret:       clientSecret,
       RedirectURIs: kcc.RedirectURIs,
   }, nil
}

func (m *KCClientManager) CreateServiceClient(ctx context.Context, id string, scopes []string) (*OAuth2Client, error) {
	token, err := m.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}
	kc := KeycloakClient{
		ID:                  id,
		Name:                      id,
		Enabled:                   true,
		Protocol:                  "openid-connect",
		ServiceAccountsEnabled:    true,
		DirectAccessGrantsEnabled: true,
	}
	data, err := json.Marshal(kc)
	if err != nil {
		return nil, fmt.Errorf("marshal KeycloakClient: %w", err)
	}
	url := fmt.Sprintf("%s/admin/realms/%s/clients", m.Endpoint, m.Realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client create: %w", err)
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		return nil, fmt.Errorf("keycloak client create: code=%d, body=%s", resp.StatusCode, b)
	}
	// Fetch client details by clientId to return info (including generated secret)
	kcc, err := m.findKeycloakClientByClientID(ctx, id)
	if err != nil {
		return nil, err
	}
	clientSecret, err := m.getClientSecret(ctx, kcc.ID)
	if err != nil {
		return nil, err
	}
   return &OAuth2Client{
       ID:     id,
       Secret: clientSecret,
   }, nil
}

// ListClients retrieves all OAuth2 clients from the provider's admin API.
func (m *KCClientManager) ListClients(ctx context.Context) ([]OAuth2Client, error) {
	token, err := m.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/admin/realms/%s/clients", m.Endpoint, m.Realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new list clients request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform list clients request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list clients request failed: status %d", resp.StatusCode)
	}
	var kcClients []KeycloakClient
	if err := json.NewDecoder(resp.Body).Decode(&kcClients); err != nil {
		return nil, fmt.Errorf("decode list clients: %w", err)
	}
	var out []OAuth2Client
	for _, kcc := range kcClients {
		out = append(out, OAuth2Client{
			ID: kcc.ClientID,
		})
	}
	return out, nil
}
