package admin

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const sessionContextKey contextKey = "admin-session"

func SessionFromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(Session)
	return session, ok
}

func RequireSession(store SessionBackend) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("admin_session")
			if err != nil || cookie.Value == "" {
				requireLogin(w, r)
				return
			}
			session, err := store.ValidateSession(r.Context(), cookie.Value, time.Now())
			if err != nil {
				requireLogin(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionContextKey, session)))
		})
	}
}

func RequireCSRF(store SessionBackend) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := SessionFromContext(r.Context())
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				token = r.FormValue("csrf_token")
			}
			if !store.ValidateCSRFToken(r.Context(), session, token) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func requireLogin(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.Header.Get("Accept"), "application/json") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}
