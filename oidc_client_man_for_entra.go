package oidc

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type EntraClientManager struct {
    tenantID     string
    clientID     string
    clientSecret string
    httpClient   *http.Client
    token        string
    tokenExpiry  time.Time
}


func NewEntraClientManager(tenantID, clientID, clientSecret string, httpClient interface{}) *EntraClientManager {
    hc, _ := httpClient.(*http.Client)
    return &EntraClientManager{
        tenantID:     tenantID,
        clientID:     clientID,
        clientSecret: clientSecret,
        httpClient:   hc,
    }
}

func (m *EntraClientManager) getAdminToken(ctx context.Context) (string, error) {
    if time.Now().Before(m.tokenExpiry) {
        return m.token, nil
    }

    data := url.Values{}
    data.Set("client_id", m.clientID)
    data.Set("scope", "https://graph.microsoft.com/.default")
    data.Set("client_secret", m.clientSecret)
    data.Set("grant_type", "client_credentials")

    req, err := http.NewRequestWithContext(ctx, "POST",
        fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", m.tenantID),
        strings.NewReader(data.Encode()))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := m.httpClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var res struct {
        AccessToken string `json:"access_token"`
        ExpiresIn   int64  `json:"expires_in"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return "", err
    }

    m.token = res.AccessToken
    m.tokenExpiry = time.Now().Add(time.Duration(res.ExpiresIn-60) * time.Second)
    return m.token, nil
}

func (m *EntraClientManager) ListClients(ctx context.Context) ([]OAuth2Client, error) {
    token, err := m.getAdminToken(ctx)
    if err != nil {
        return nil, err
    }

    req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/applications", nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := m.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var res struct {
        Value []struct {
            ID          string `json:"id"`
            DisplayName string `json:"displayName"`
        } `json:"value"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return nil, err
    }

    var clients []OAuth2Client
    for _, app := range res.Value {
        clients = append(clients, OAuth2Client{
            ID:   app.ID,
            Name: app.DisplayName,
        })
    }

    return clients, nil
}

func (m *EntraClientManager) GetClientSecret(ctx context.Context, clientID string) (string, error) {
    token, err := m.getAdminToken(ctx)
    if err != nil {
        return "", err
    }

    url := fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s", clientID)
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return "", err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := m.httpClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var res struct {
        PasswordCredentials []struct {
            SecretText string `json:"secretText"`
        } `json:"passwordCredentials"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return "", err
    }

    if len(res.PasswordCredentials) == 0 {
        return "", errors.New("no client secret found")
    }

    return res.PasswordCredentials[0].SecretText, nil
}

func (m *EntraClientManager) findClientByClientID(ctx context.Context, clientId string) (*OAuth2Client, error) {
    token, err := m.getAdminToken(ctx)
    if err != nil {
        return nil, err
    }

    filter := url.QueryEscape(fmt.Sprintf("identifierUris/any(uri:uri eq '%s')", clientId))
    req, err := http.NewRequestWithContext(ctx, "GET",
        fmt.Sprintf("https://graph.microsoft.com/v1.0/applications?$filter=%s", filter), nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := m.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var res struct {
        Value []struct {
            ID          string `json:"id"`
            DisplayName string `json:"displayName"`
        } `json:"value"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return nil, err
    }

    if len(res.Value) == 0 {
        return nil, errors.New("client not found")
    }

    return &OAuth2Client{
        ID:   res.Value[0].ID,
        Name: res.Value[0].DisplayName,
    }, nil
}

func (m *EntraClientManager) CreateServiceClient(ctx context.Context, name string, scopes []string) (*OAuth2Client, error) {
    token, err := m.getAdminToken(ctx)
    if err != nil {
        return nil, err
    }

    payload := fmt.Sprintf(`{
        "displayName": "%s",
        "signInAudience": "AzureADMyOrg",
        "requiredResourceAccess": [],
        "passwordCredentials": [{
            "displayName": "Default"
        }]
    }`, name)

    req, err := http.NewRequestWithContext(ctx, "POST", "https://graph.microsoft.com/v1.0/applications",
        strings.NewReader(payload))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    resp, err := m.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var res struct {
        ID    string `json:"id"`
        AppID string `json:"appId"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return nil, err
    }

    // Note: Azure does not return the secret in this response; must create separately if needed

    return &OAuth2Client{
        ID:   res.ID,
        Name: name,
    }, nil
}

// NOTE: CreateUserClient is not supported in Entra ID as dynamic public client creation isn't allowed.
// To satisfy the interface, return an error if called.
func (m *EntraClientManager) CreateUserClient(ctx context.Context, id string, redirectURIs, scopes []string) (*OAuth2Client, error) {
    return nil, fmt.Errorf("CreateUserClient is not supported for EntraClientManager (Azure Entra)")
}
