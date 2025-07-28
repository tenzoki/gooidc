package oidc

import (
    "context"
)

// OIDCClientManager defines the interface for OIDC client operations, implemented by both KC and Entra managers.
type OIDCClientManager interface {
    // CreateUserClient is not supported for Entra, so should return an error if invoked.
    CreateUserClient(ctx context.Context, id string, redirectURIs, scopes []string) (*OAuth2Client, error)
    CreateServiceClient(ctx context.Context, id string, scopes []string) (*OAuth2Client, error)
    // (extend with other shared/needed methods, e.g. ListClients, GetClientSecret, etc., if needed)
}

// OAuth2Client is a generic OIDC OAuth2 client info struct, used by both managers.
type OAuth2Client struct {
    ID           string
    Name         string
    Secret       string
    RedirectURIs []string
}

// Factory method for OIDCClientManager
func NewOIDCClientManager(provider string, args ...interface{}) OIDCClientManager {
    switch provider {
    case "kc":
        // expect: endpoint, httpClient
        return NewKCClientManager(args[0].(string), args[1])
    case "entra":
        // expect: tenantID, clientID, clientSecret, httpClient
        return NewEntraClientManager(args[0].(string), args[1].(string), args[2].(string), args[3])
    default:
        return nil
    }
}
