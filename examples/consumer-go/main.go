// Command consumer-go shows the consumer-side validation boundary. It never loads
// or prints a device private key; the device app owns challenge signing locally.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"keypair-auth-service/internal/auth"
)

func main() {
	baseURL := valueOr("AUTH_SERVICE_URL", "https://auth.example.internal")
	issuer := valueOr("AUTH_ISSUER", baseURL)
	audience := valueOr("AUTH_CLIENT_ID", "app-a")
	verifier := &auth.ConsumerVerifier{
		Issuer: issuer,
		Audience: audience,
		Fetcher: &auth.HTTPJWKSFetcher{URL: baseURL + "/.well-known/jwks.json", Client: http.DefaultClient},
		CacheMaxAge: 5 * time.Minute,
	}

	// The device app obtains a nonce, signs the canonical challenge with its
	// platform-secure private key, and POSTs client_id with the signature to
	// /api/auth/verify. Keep the resulting access token confidential.
	rawToken := os.Getenv("DEVICE_ACCESS_TOKEN")
	if rawToken == "" {
		fmt.Println("set DEVICE_ACCESS_TOKEN to run local verification")
		return
	}
	claims, err := verifier.Verify(context.Background(), rawToken, time.Now())
	if err != nil {
		fmt.Println("token rejected")
		return
	}
	fmt.Println("authenticated device:", claims.DeviceID, "user:", claims.UserID)
}

func valueOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
