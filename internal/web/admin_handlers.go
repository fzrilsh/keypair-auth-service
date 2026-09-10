package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"keypair-auth-service/internal/admin"
	"keypair-auth-service/internal/auth"
)

type AdminHandlers struct {
	Auth      *auth.Service
	Admin     *admin.Service
	Sessions  admin.SessionBackend
	InviteTTL time.Duration
}

func (h AdminHandlers) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderLogin(w, "")
		return
	}
	if err := r.ParseForm(); err != nil {
		renderLogin(w, "Invalid form")
		return
	}
	session, err := h.Admin.Login(r.Context(), r.FormValue("email"), []byte(r.FormValue("password")))
	if err != nil {
		renderLogin(w, "Invalid credentials")
		return
	}
	setAdminCookies(w, session)
	http.Redirect(w, r, "/admin/devices", http.StatusFound)
}

func (h AdminHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("admin_session"); err == nil {
		h.Admin.Logout(cookie.Value)
	}
	clearCookie(w, "admin_session", true)
	clearCookie(w, "admin_csrf", false)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (h AdminHandlers) Devices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.Auth.ListDevices(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	data := struct {
		Devices   []auth.Device
		CSRFToken string
	}{Devices: devices, CSRFToken: csrfFromRequest(r)}
	_ = devicesTemplate.Execute(w, data)
}

func (h AdminHandlers) Invites(w http.ResponseWriter, r *http.Request) {
	invites, err := h.Auth.ListInvites(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	data := struct {
		Invites   []auth.Invite
		CSRFToken string
	}{Invites: invites, CSRFToken: csrfFromRequest(r)}
	_ = invitesTemplate.Execute(w, data)
}

func (h AdminHandlers) CreateInvite(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	userID, err := uuid.Parse(r.FormValue("user_id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	lifetime := h.InviteTTL
	if lifetime <= 0 {
		lifetime = 15 * time.Minute
	}
	invite, err := h.Auth.CreateInvite(r.Context(), userID, lifetime)
	if err != nil {
		http.Error(w, "unable to create invite", http.StatusInternalServerError)
		return
	}
	data := struct {
		Invite    auth.InviteResult
		CSRFToken string
	}{Invite: invite, CSRFToken: csrfFromRequest(r)}
	_ = inviteCreatedTemplate.Execute(w, data)
}

func (h AdminHandlers) Approve(w http.ResponseWriter, r *http.Request) { h.transition(w, r, true) }
func (h AdminHandlers) Revoke(w http.ResponseWriter, r *http.Request)  { h.transition(w, r, false) }

func (h AdminHandlers) transition(w http.ResponseWriter, r *http.Request, approve bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if approve {
		err = h.Auth.Approve(r.Context(), id)
	} else {
		err = h.Auth.Revoke(r.Context(), id)
	}
	if errors.Is(err, auth.ErrConflict) {
		http.Error(w, "invalid state transition", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		status := "revoked"
		if approve {
			status = "approved"
		}
		_, _ = fmt.Fprintf(w, "<span>%s</span>", status)
		return
	}
	http.Redirect(w, r, "/admin/devices", http.StatusFound)
}

func setAdminCookies(w http.ResponseWriter, session admin.Session) {
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: session.ID, Path: "/admin", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	http.SetCookie(w, &http.Cookie{Name: "admin_csrf", Value: session.CSRFToken, Path: "/admin", HttpOnly: false, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func clearCookie(w http.ResponseWriter, name string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/admin", HttpOnly: httpOnly, Secure: true, MaxAge: -1})
}

func csrfFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie("admin_csrf"); err == nil {
		return cookie.Value
	}
	return ""
}

func renderLogin(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><title>Admin login</title><link rel="stylesheet" href="/static/app.css"><form method="post"><label>Email <input name="email" type="email" autocomplete="username"></label><label>Password <input name="password" type="password" autocomplete="current-password"></label><button>Login</button><p>%s</p></form>`, template.HTMLEscapeString(message))
}

var devicesTemplate = template.Must(template.New("devices").Parse(`<!doctype html><title>Devices</title><link rel="stylesheet" href="/static/app.css"><h1>Devices</h1><nav><a href="/admin/invites">Invites</a> <a href="/admin/docs">API docs</a></nav><table><tr><th>ID</th><th>User</th><th>Status</th><th>Action</th></tr>{{range .Devices}}<tr><td>{{.ID}}</td><td>{{.UserID}}</td><td>{{.Status}}</td><td>{{if eq .Status "pending"}}<form method="post" action="/admin/devices/{{.ID}}/approve"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><button>Approve</button></form>{{else if eq .Status "approved"}}<form method="post" action="/admin/devices/{{.ID}}/revoke"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><button>Revoke</button></form>{{end}}</td></tr>{{end}}</table><form method="post" action="/admin/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button>Logout</button></form>`))
var invitesTemplate = template.Must(template.New("invites").Parse(`<!doctype html><title>Invites</title><link rel="stylesheet" href="/static/app.css"><h1>Invites</h1><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>User UUID <input name="user_id" required></label><button>Generate invite</button></form><table><tr><th>Prefix</th><th>User</th><th>Expires</th><th>Used</th></tr>{{range .Invites}}<tr><td>{{.Prefix}}</td><td>{{.UserID}}</td><td>{{.ExpiresAt}}</td><td>{{.UsedAt}}</td></tr>{{end}}</table>`))
var inviteCreatedTemplate = template.Must(template.New("invite-created").Parse(`<!doctype html><title>Invite created</title><h1>Invite created</h1><p>Copy this token now. It cannot be retrieved later:</p><textarea readonly rows="3" cols="64">{{.Invite.Token}}</textarea><p>Prefix: {{.Invite.Prefix}} — expires: {{.Invite.ExpiresAt}}</p><a href="/admin/invites">Back</a>`))
