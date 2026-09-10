package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"keypair-auth-service/internal/auth"
)

func TestKeyRotationConsumerOverlap(t *testing.T) {
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKeys := auth.SigningKeys{ActivePrivate: oldPrivate, ActivePublic: oldPublic, ActiveKID: "key-a"}
	rotatedKeys := auth.SigningKeys{ActivePrivate: newPrivate, ActivePublic: newPublic, ActiveKID: "key-b", PreviousPublic: oldPublic, PreviousKID: "key-a"}
	device := auth.Device{ID: uuid.New(), UserID: uuid.New()}
	oldToken, err := auth.IssueDeviceJWT(oldKeys, "integration", "app-a", device, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := auth.IssueDeviceJWT(rotatedKeys, "integration", "app-a", device, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rotatedKeys.JWKS())
	}))
	defer server.Close()
	verifier := &auth.ConsumerVerifier{Issuer: "integration", Audience: "app-a", Fetcher: &auth.HTTPJWKSFetcher{URL: server.URL, Client: server.Client()}, CacheMaxAge: time.Minute}
	if _, err := verifier.Verify(context.Background(), oldToken, time.Now()); err != nil {
		t.Fatalf("old token should verify during overlap: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), newToken, time.Now()); err != nil {
		t.Fatalf("new token should verify after rotation: %v", err)
	}

	removed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(auth.SigningKeys{ActivePrivate: newPrivate, ActivePublic: newPublic, ActiveKID: "key-b"}.JWKS())
	}))
	defer removed.Close()
	withoutPrevious := &auth.ConsumerVerifier{Issuer: "integration", Audience: "app-a", Fetcher: &auth.HTTPJWKSFetcher{URL: removed.URL, Client: removed.Client()}, CacheMaxAge: time.Minute}
	if _, err := withoutPrevious.Verify(context.Background(), oldToken, time.Now()); err == nil {
		t.Fatal("old token should fail after previous key is removed")
	}
}
