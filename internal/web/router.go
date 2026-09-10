package web

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"keypair-auth-service/internal/admin"
	"keypair-auth-service/internal/httputil"
	"keypair-auth-service/internal/web/docs"
	"keypair-auth-service/internal/web/static"
)

type Dependencies struct {
	API           APIHandlers
	Admin         AdminHandlers
	AdminSessions admin.SessionBackend
	JWKS          http.Handler
	Ready         func(context.Context) error
}

func NewRouter(deps Dependencies) http.Handler {
	r := chi.NewRouter()
	r.Use(httputil.SecurityHeaders)
	r.Get("/healthz", HealthHandler)
	if deps.Ready == nil {
		deps.Ready = func(context.Context) error { return nil }
	}
	r.Get("/readyz", ReadyHandler(deps.Ready))
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(static.FS))))
	if deps.JWKS != nil {
		r.Get("/.well-known/jwks.json", deps.JWKS.ServeHTTP)
	}
	r.Post("/api/devices/enroll", deps.API.Enroll)
	r.Get("/api/auth/challenge", deps.API.Challenge)
	r.Post("/api/auth/verify", deps.API.Verify)
	r.Get("/admin/login", deps.Admin.Login)
	r.Post("/admin/login", deps.Admin.Login)
	adminGroup := chi.NewRouter()
	if deps.AdminSessions != nil {
		adminGroup.Use(admin.RequireSession(deps.AdminSessions))
	} else {
		adminGroup.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "admin authentication unavailable", http.StatusServiceUnavailable)
			})
		})
	}
	adminGroup.Get("/devices", deps.Admin.Devices)
	adminGroup.Get("/devices/{id}/scopes", deps.Admin.DeviceScopes)
	adminGroup.Get("/invites", deps.Admin.Invites)
	adminGroup.Get("/scopes", deps.Admin.Scopes)
	if deps.AdminSessions != nil {
		adminGroup.With(admin.RequireCSRF(deps.AdminSessions)).Post("/invites", deps.Admin.CreateInvite)
		adminGroup.With(admin.RequireCSRF(deps.AdminSessions)).Post("/invites/{id}/remove", deps.Admin.RemoveInvite)
		adminGroup.With(admin.RequireCSRF(deps.AdminSessions)).Post("/logout", deps.Admin.Logout)
		adminGroup.With(admin.RequireCSRF(deps.AdminSessions)).Post("/devices/{id}/approve", deps.Admin.Approve)
		adminGroup.With(admin.RequireCSRF(deps.AdminSessions)).Post("/devices/{id}/revoke", deps.Admin.Revoke)
		adminGroup.With(admin.RequireCSRF(deps.AdminSessions)).Post("/devices/{id}/scopes", deps.Admin.ReplaceDeviceScopes)
		adminGroup.With(admin.RequireCSRF(deps.AdminSessions)).Post("/scopes", deps.Admin.CreateScope)
		adminGroup.With(admin.RequireCSRF(deps.AdminSessions)).Post("/scopes/{id}/{action}", deps.Admin.ToggleScope)
	}
	adminGroup.Get("/docs", func(w http.ResponseWriter, req *http.Request) { docs.Handler().ServeHTTP(w, req) })
	adminGroup.Get("/docs/openapi.yaml", func(w http.ResponseWriter, req *http.Request) { docs.SpecHandler().ServeHTTP(w, req) })
	adminGroup.Handle("/docs/assets/*", http.StripPrefix("/admin/docs/assets/", docs.AssetHandler()))
	r.Mount("/admin", adminGroup)
	return r
}
