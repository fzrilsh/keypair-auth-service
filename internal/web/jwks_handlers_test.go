package web

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"keypair-auth-service/internal/auth"
)

func TestJWKSHandlerIsPublicAndContainsNoPrivateFields(t *testing.T) {
	keys := testSigningKeysForWeb(t)
	handler := JWKSHandler{Keys: keys, CacheMaxAge: time.Minute}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "json") {
		t.Fatalf("unexpected response: %d", response.Code)
	}
	if !strings.Contains(response.Header().Get("Cache-Control"), "max-age=60") {
		t.Fatalf("unexpected cache header: %q", response.Header().Get("Cache-Control"))
	}
	if strings.Contains(response.Body.String(), "private") || !strings.Contains(response.Body.String(), "active") {
		t.Fatalf("unexpected JWKS: %s", response.Body.String())
	}
}

func testSigningKeysForWeb(t *testing.T) auth.SigningKeys {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return auth.SigningKeys{ActivePrivate: private, ActivePublic: public, ActiveKID: "active"}
}
