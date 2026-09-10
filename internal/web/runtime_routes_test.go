package web

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"keypair-auth-service/internal/admin"
	"keypair-auth-service/internal/auth"
)

func newRouterFixture(t *testing.T) (http.Handler, *auth.Service, *admin.Service, *admin.SessionStore) {
	t.Helper()
	store := auth.NewMemoryStore()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(store, auth.ServiceConfig{
		Keys:             auth.SigningKeys{ActivePrivate: private, ActivePublic: public, ActiveKID: "test-key"},
		AllowedAudiences: map[string]struct{}{"app-a": {}}, Issuer: "test",
		NonceTTL: time.Minute, TimestampSkew: time.Minute, JWTLifetime: 15 * time.Minute,
	})
	accounts := admin.NewAccountStore()
	passwordHash, err := admin.HashPassword([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	accounts.Add(admin.AdminAccount{ID: uuid.New(), Email: "admin@example.com", PasswordHash: passwordHash})
	sessions := admin.NewSessionStore([]byte("01234567890123456789012345678901"))
	adminService := admin.NewService(accounts, sessions, time.Hour)
	api := APIHandlers{Auth: service, RequestBodyLimit: 1 << 20}
	adminHandlers := AdminHandlers{Auth: service, Admin: adminService, Sessions: sessions}
	return NewRouter(Dependencies{API: api, Admin: adminHandlers, AdminSessions: sessions, JWKS: JWKSHandler{Keys: auth.SigningKeys{ActivePrivate: private, ActivePublic: public, ActiveKID: "test-key"}, CacheMaxAge: time.Minute}}), service, adminService, sessions
}

func TestRouterServesEnrollmentAndChallengeRoutes(t *testing.T) {
	router, service, _, _ := newRouterFixture(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	invite, err := service.CreateInvite(t.Context(), userID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"invite_token":"` + invite.Token + `","public_key":"` + encode(publicKey) + `"}`
	enroll := httptest.NewRequest(http.MethodPost, "/api/devices/enroll", strings.NewReader(body))
	enroll.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, enroll)
	if response.Code != http.StatusCreated {
		t.Fatalf("enroll status %d: %s", response.Code, response.Body.String())
	}
}

func TestRouterProtectsAdminDocsAndServesLogin(t *testing.T) {
	router, _, _, _ := newRouterFixture(t)
	login := httptest.NewRecorder()
	router.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if login.Code != http.StatusOK {
		t.Fatalf("login status %d", login.Code)
	}
	docs := httptest.NewRecorder()
	router.ServeHTTP(docs, httptest.NewRequest(http.MethodGet, "/admin/docs", nil))
	if docs.Code != http.StatusFound {
		t.Fatalf("docs status %d", docs.Code)
	}
}

func encode(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func TestJWKSRouteIsPublic(t *testing.T) {
	router, _, _, _ := newRouterFixture(t)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "json") {
		t.Fatalf("unexpected JWKS response: %d %q", response.Code, response.Body.String())
	}
}
