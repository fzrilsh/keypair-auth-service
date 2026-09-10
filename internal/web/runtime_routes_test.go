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

func TestRemoveInviteRouteRequiresCSRFAndUsesOpaqueID(t *testing.T) {
	router, service, _, sessions := newRouterFixture(t)
	created, err := service.CreateInvite(t.Context(), uuid.New(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	invites, err := service.ListInvites(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 1 || invites[0].ID == uuid.Nil {
		t.Fatalf("unexpected invites: %+v", invites)
	}
	inviteID := invites[0].ID

	session, err := sessions.Create(uuid.New(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	path := "/admin/invites/" + inviteID.String() + "/remove"
	withoutCSRF := httptest.NewRequest(http.MethodPost, path, nil)
	withoutCSRF.AddCookie(&http.Cookie{Name: "admin_session", Value: session.ID})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, withoutCSRF)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected missing CSRF rejection, got %d", response.Code)
	}

	malformed := httptest.NewRequest(http.MethodPost, "/admin/invites/not-a-uuid/remove", nil)
	malformed.AddCookie(&http.Cookie{Name: "admin_session", Value: session.ID})
	malformed.Header.Set("X-CSRF-Token", session.CSRFToken)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, malformed)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected malformed ID rejection, got %d", response.Code)
	}

	get := httptest.NewRequest(http.MethodGet, path, nil)
	get.AddCookie(&http.Cookie{Name: "admin_session", Value: session.ID})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, get)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected GET remove to be disallowed, got %d", response.Code)
	}

	remove := httptest.NewRequest(http.MethodPost, path, nil)
	remove.AddCookie(&http.Cookie{Name: "admin_session", Value: session.ID})
	remove.Header.Set("X-CSRF-Token", session.CSRFToken)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, remove)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/admin/invites" {
		t.Fatalf("unexpected remove response: %d %q", response.Code, response.Header().Get("Location"))
	}
	remaining, err := service.ListInvites(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("invite was not removed: %+v", remaining)
	}
	_ = created
}

func TestInvitesPageRendersOpaqueRemoveID(t *testing.T) {
	router, service, _, sessions := newRouterFixture(t)
	if _, err := service.CreateInvite(t.Context(), uuid.New(), time.Minute); err != nil {
		t.Fatal(err)
	}
	invites, err := service.ListInvites(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessions.Create(uuid.New(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/invites", nil)
	request.AddCookie(&http.Cookie{Name: "admin_session", Value: session.ID})
	request.AddCookie(&http.Cookie{Name: "admin_csrf", Value: session.CSRFToken})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("invites page status %d", response.Code)
	}
	expectedAction := `action="/admin/invites/` + invites[0].ID.String() + `/remove"`
	if !strings.Contains(response.Body.String(), expectedAction) || !strings.Contains(response.Body.String(), "name=\"csrf_token\"") || !strings.Contains(response.Body.String(), `src="/static/uuid.js"`) || !strings.Contains(response.Body.String(), `id="generate-user-id"`) {
		t.Fatalf("remove form or UUID generator missing from invites page: %s", response.Body.String())
	}
}

func TestScopeAdminRoutesRequireCSRFAndRenderAssignments(t *testing.T) {
	router, service, _, sessions := newRouterFixture(t)
	session, err := sessions.Create(uuid.New(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "admin_session", Value: session.ID}
	csrfCookie := &http.Cookie{Name: "admin_csrf", Value: session.CSRFToken}

	getScopes := httptest.NewRequest(http.MethodGet, "/admin/scopes", nil)
	getScopes.AddCookie(cookie)
	getScopes.AddCookie(csrfCookie)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, getScopes)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Scope name") {
		t.Fatalf("unexpected scopes page: %d %s", response.Code, response.Body.String())
	}

	withoutCSRF := httptest.NewRequest(http.MethodPost, "/admin/scopes", strings.NewReader("name=profile%3Aread"))
	withoutCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withoutCSRF.AddCookie(cookie)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, withoutCSRF)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected missing CSRF rejection, got %d", response.Code)
	}

	create := httptest.NewRequest(http.MethodPost, "/admin/scopes", strings.NewReader("name=profile%3Aread"))
	create.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	create.Header.Set("X-CSRF-Token", session.CSRFToken)
	create.AddCookie(cookie)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, create)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/admin/scopes" {
		t.Fatalf("unexpected scope create response: %d %q", response.Code, response.Header().Get("Location"))
	}

	scopes, err := service.ListScopes(t.Context())
	if err != nil || len(scopes) != 1 {
		t.Fatalf("unexpected catalog: %v %+v", err, scopes)
	}
	invites := httptest.NewRequest(http.MethodGet, "/admin/invites", nil)
	invites.AddCookie(cookie)
	invites.AddCookie(csrfCookie)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, invites)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `name="scope_id"`) || !strings.Contains(response.Body.String(), scopes[0].ID.String()) {
		t.Fatalf("scope checkbox missing from invite page: %d %s", response.Code, response.Body.String())
	}
}

func TestUUIDGeneratorAssetIsServed(t *testing.T) {
	router, _, _, _ := newRouterFixture(t)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/static/uuid.js", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "crypto.randomUUID") {
		t.Fatalf("UUID asset was not served: %d %s", response.Code, response.Body.String())
	}
}
