# OIDC Utilities - Go Modules Overview

This repository provides utility functions for working with JWT payloads and for administering OIDC clients (e.g., on a Keycloak server).

## Module & Function Overview

### 1. `decode_payload_map.go`

#### - `DecodePayloadToMap(seg string) (map[string]interface{}, error)`
**Purpose:** Decodes the payload (middle part) of a JWT, which is a base64-encoded JSON string, into a Go map (`map[string]interface{}`).
**How:** It adds padding to the string if necessary, decodes the string from base64, and then unmarshals the JSON.

---

### 2. `jwt_decoder.go`

#### - `func (a *audList) UnmarshalJSON(data []byte) error`
**Purpose:** Custom unmarshal logic for the JWT `aud` claim, so it accepts both a string or an array of strings.
**How:** Tries to unmarshal as a string, if that fails, tries as an array of strings; errors otherwise.

#### - `DecodeJWT(token string) (*JWT, error)`
**Purpose:** Decodes a JWT string into its header, payload, and signature, parsing the payload (claims) into a strongly-typed struct.
**How:** Splits the JWT into three parts (header, payload, signature), base64-decodes each, and then JSON-unmarshals the results.

#### - `decodeSegment(seg string) ([]byte, error)`
**Purpose:** Helper for decoding single JWT base64url-encoded segments, with padding fixup.
**How:** Adds base64 padding if needed, and decodes.

---

### 3. `oidc_client_man.go`

#### - `findKeycloakClientByClientID(ctx context.Context, clientId string) (*KeycloakClient, error)`
**Purpose:** Looks up a Keycloak client (by `clientId`) using admin privileges.
**How:** Calls Keycloak admin REST API to retrieve client JSON.

#### - `getClientSecret(ctx context.Context, clientUuid string) (string, error)`
**Purpose:** Retrieves the secret for a Keycloak client, using admin API and client UUID.
**How:** Calls relevant Keycloak API endpoint, extracts secret from JSON response.

#### - `NewClientManager(endpoint string, httpClient *http.Client) *ClientManager`
**Purpose:** Constructor for `ClientManager`, sets up struct for OIDC admin usage.
**How:** Reads config from environment variables, fills struct.

#### - `getAdminToken(ctx context.Context) (string, error)`
**Purpose:** Retrieves (and caches) admin access token for Keycloak REST API.
**How:** Submits password grant to Keycloak's `admin-cli` endpoint.

#### - `CreateUserClient(ctx context.Context, id string, redirectURIs, scopes []string) (*OAuth2Client, error)`
**Purpose:** Creates a user-type OAuth2 client in Keycloak with the specified properties.
**How:** Marshals client config, POSTs to Keycloak API, extracts details and secret for return.

#### - `CreateServiceClient(ctx context.Context, id string, scopes []string) (*OAuth2Client, error)`
**Purpose:** Creates a service-account OAuth2 client in Keycloak.
**How:** POSTs suitable config, returns the registration (including secret).

#### - `ListClients(ctx context.Context) ([]OAuth2Client, error)`
**Purpose:** Lists all OAuth2 clients visible to admin in the current Keycloak instance.
**How:** Calls Keycloak API to retrieve, parses into Go structs.

---

**If you want more details on any specific function (like parameter/return types or to see the implementation), check the respective Go file for documentation or implementation specifics.**
