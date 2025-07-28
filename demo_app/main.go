package main

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/user/oidc" // Import local oidc package (relative import, adjust in real project)
)

func main() {
    ctx := context.Background()
    httpClient := &http.Client{Timeout: 10 * time.Second}

    // --- Example: Using Keycloak implementation ---
    fmt.Println("== Keycloak example ==")
    kcMgr := oidc.NewOIDCClientManager("kc", "http://localhost:8080", httpClient)

    // Try to create a user client (would need working endpoint)
    userClient, err := kcMgr.CreateUserClient(ctx, "demo-client", []string{"http://localhost/cb"}, []string{"openid"})
    if err != nil {
        fmt.Printf("KC CreateUserClient error: %v\n", err)
    } else {
        fmt.Printf("KC user client: %+v\n", userClient)
    }

    // Try to create a service client
    svcClient, err := kcMgr.CreateServiceClient(ctx, "service-client", []string{"openid"})
    if err != nil {
        fmt.Printf("KC CreateServiceClient error: %v\n", err)
    } else {
        fmt.Printf("KC service client: %+v\n", svcClient)
    }


    // --- Example: Using Entra implementation ---
    fmt.Println("== Entra example ==")
    entraMgr := oidc.NewOIDCClientManager(
        "entra",
        "your-tenant-id",
        "your-client-id",
        "your-client-secret",
        httpClient,
    )

    // Try to create a service client (Entra only allows service clients)
    entraSvc, err := entraMgr.CreateServiceClient(ctx, "sample-entra-client", []string{"/.default"})
    if err != nil {
        fmt.Printf("Entra CreateServiceClient error: %v\n", err)
    } else {
        fmt.Printf("Entra service client: %+v\n", entraSvc)
    }

    // Try to create a user client (which should error on Entra)
    _, err = entraMgr.CreateUserClient(ctx, "some-user-app", []string{"http://localhost/cb"}, []string{"openid"})
    if err != nil {
        fmt.Printf("Entra CreateUserClient (should fail): %v\n", err)
    }
}
