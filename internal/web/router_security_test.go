package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"keypair-auth-service/internal/admin"
)

func TestDocsRoutesRequireAdminSession(t *testing.T) {
	store := admin.NewSessionStore([]byte(strings.Repeat("s", 32)))
	router := NewRouter(Dependencies{AdminSessions: store})
	unauthenticated := httptest.NewRecorder()
	router.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/admin/docs", nil))
	if unauthenticated.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", unauthenticated.Code)
	}

	session, err := store.Create(uuid.New(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authenticated := httptest.NewRequest(http.MethodGet, "/admin/docs", nil)
	authenticated.AddCookie(&http.Cookie{Name: "admin_session", Value: session.ID})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, authenticated)
	if response.Code != http.StatusOK {
		t.Fatalf("expected docs page, got %d", response.Code)
	}
}

func TestDocsYAMLRequiresAdminSession(t *testing.T) {
	store := admin.NewSessionStore([]byte(strings.Repeat("s", 32)))
	router := NewRouter(Dependencies{AdminSessions: store})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/docs/openapi.yaml", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", response.Code)
	}
}

func TestDocsAssetsRequireAdminSession(t *testing.T) {
	store := admin.NewSessionStore([]byte(strings.Repeat("s", 32)))
	router := NewRouter(Dependencies{AdminSessions: store})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/docs/assets/swagger-ui.css", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", response.Code)
	}
}
