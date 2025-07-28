# gooidc — OIDC & JWT Utilities for Go

Utilities and interfaces for decoding JWTs and administering OIDC clients in Go, with support for Keycloak and Azure Entra ID (formerly Azure AD). Usable as a Go module: `github.com/tenzoki/gooidc`.

---

## Features

- Decode JWTs to Go structs or arbitrary maps.
- Programmatically create/administer OIDC clients — both user and service clients for [Keycloak](https://www.keycloak.org/) or [Azure Entra ID](https://azure.microsoft.com/en-us/products/entra-id) (enterprise only allows service clients).
- High-level, provider-agnostic interface for admin operations (via a factory method).

---

## Installation

```
go get github.com/tenzoki/gooidc
```

```go
import "github.com/tenzoki/gooidc"
```

---

## OIDC Client Management Usage

### Unified Interface

Use the factory function to instantiate a provider-specific client manager:

```go
mgr := gooidc.NewOIDCClientManager(providerName, args...)
```

- For Keycloak: `providerName = "kc"`, args = endpointURL (string), httpClient
- For Entra ID: `providerName = "entra"`, args = tenantID, clientID, clientSecret, httpClient

### Example: Keycloak

```go
import (
  "context"
  "net/http"
  "github.com/tenzoki/gooidc"
)

mgr := gooidc.NewOIDCClientManager("kc", "http://localhost:8080", &http.Client{})

userClient, err := mgr.CreateUserClient(context.Background(), "demo-client", []string{"http://localhost/cb"}, []string{"openid"})
svcClient, err := mgr.CreateServiceClient(context.Background(), "service-client", []string{"openid"})
```

#### Keycloak configuration
- Reads realm, admin user/pass from environment: `KEYCLOAK_REALM`, `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD` (defaults: `maccs-demo`, `admin`, `admin`).

### Example: Azure Entra ID (Azure AD)

```go
import (
  "context"
  "net/http"
  "github.com/tenzoki/gooidc"
)

mgr := gooidc.NewOIDCClientManager(
  "entra",
  "your-tenant-id",
  "your-client-id",
  "your-client-secret",
  &http.Client{},
)

// Only service clients supported
svcClient, err := mgr.CreateServiceClient(context.Background(), "service-app", []string{"/.default"})

// This will always error:
_, err := mgr.CreateUserClient(context.Background(), "app-client", []string{"http://localhost/cb"}, []string{"openid"})
// err != nil (not supported)
```

---

## JWT Decoding Utilities

- `DecodePayloadToMap(seg string) (map[string]interface{}, error)` — Convert a JWT payload segment to a map.
- `DecodeJWT(token string) (*JWT, error)` — Parse a full JWT (header, payload, signature, Go types for claims).
- Handles `aud` claim as string or array.

---

## File & API Overview

| File                       | Key Methods / Types |
|----------------------------|---------------------|
| `decode_payload_map.go`    | `DecodePayloadToMap()` |
| `jwt_decoder.go`           | `DecodeJWT()`, type `JWT`, claim parsing |
| `oidc_client_manager.go`   | `OIDCClientManager` interface, `OAuth2Client`, factory, exported |
| `oidc_client_man_for_kc.go`| Keycloak implementation |
| `oidc_client_man_for_entra.go` | Entra/Azure implementation |

---

## Demo App Example

See `demo_app/main.go` for a concise example covering both providers.

```go
package main

import (
    "context"
    "fmt"
    "net/http"
    "time"
    "github.com/tenzoki/gooidc"
)

func main() {
    ctx := context.Background()
    httpClient := &http.Client{Timeout: 10 * time.Second}

    // Keycloak example
    kcMgr := gooidc.NewOIDCClientManager("kc", "http://localhost:8080", httpClient)
    userClient, err := kcMgr.CreateUserClient(ctx, "demo-client", []string{"http://localhost/cb"}, []string{"openid"})
    svcClient, err := kcMgr.CreateServiceClient(ctx, "service-client", []string{"openid"})

    // Entra example
    entraMgr := gooidc.NewOIDCClientManager("entra", "your-tenant-id", "your-client-id", "your-client-secret", httpClient)
    entraSvc, err := entraMgr.CreateServiceClient(ctx, "entra-client", []string{"/.default"})
    _, err = entraMgr.CreateUserClient(ctx, "not-allowed", []string{"http://localhost/cb"}, []string{"openid"})
    // ...
}
```

---

## Compatibility

- Go 1.20+
- Keycloak (tested against 18+), or Azure Entra ID

---

## License

MIT or Apache 2.0 (see repo).
