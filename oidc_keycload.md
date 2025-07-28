# OIDC & Keycloak Utilities Overview

## common oidc

### decode_payload_map.go

- **DecodePayloadToMap(seg string) (map[string]interface{}, error)**  
  Decodes the base64url-encoded payload part of a JWT into a Go map (`map[string]interface{}`).

### jwt_decoder.go

- **(a *audList) UnmarshalJSON(data []byte) error**  
  Custom JSON unmarshal for the JWT `aud` claim, accepting both a string and an array of strings.

- **DecodeJWT(token string) (*JWT, error)**  
  Splits a JWT string, decodes the parts, and parses them as header, payload, and signature.

- **decodeSegment(seg string) ([]byte, error)**  
  Base64url-decodes a JWT segment, applying padding if needed.

---

## keycload specfic

### oidc_client_man.go

- **findKeycloakClientByClientID(ctx context.Context, clientId string) (*KeycloakClient, error)**  
  Looks up a Keycloak client by clientId using admin REST API.

- **getClientSecret(ctx context.Context, clientUuid string) (string, error)**  
  Retrieves a Keycloak client's secret using the admin REST API and client UUID.

- **NewClientManager(endpoint string, httpClient *http.Client) *ClientManager**  
  Constructs a ClientManager for Keycloak administration, using env vars for configuration.

- **getAdminToken(ctx context.Context) (string, error)**  
  Retrieves (and caches) an admin access token for Keycloak REST API operations.

- **CreateUserClient(ctx context.Context, id string, redirectURIs, scopes []string) (*OAuth2Client, error)**  
  Registers a new user-style OAuth2 client in Keycloak and returns the client info and secret.

- **CreateServiceClient(ctx context.Context, id string, scopes []string) (*OAuth2Client, error)**  
  Registers a new service-account OAuth2 client in Keycloak.

- **ListClients(ctx context.Context) ([]OAuth2Client, error)**  
  Lists all OAuth2 clients known to admin in Keycloak.

