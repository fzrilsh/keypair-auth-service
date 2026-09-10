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
	activeScopes, err := h.Auth.ListActiveScopes(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	data := struct {
		Invites      []auth.Invite
		ActiveScopes []auth.Scope
		CSRFToken    string
	}{Invites: invites, ActiveScopes: activeScopes, CSRFToken: csrfFromRequest(r)}
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
	var scopeIDs []uuid.UUID
	for _, rawID := range r.Form["scope_id"] {
		scopeID, err := uuid.Parse(rawID)
		if err != nil {
			http.Error(w, "invalid scope", http.StatusBadRequest)
			return
		}
		scopeIDs = append(scopeIDs, scopeID)
	}
	lifetime := h.InviteTTL
	if lifetime <= 0 {
		lifetime = 15 * time.Minute
	}
	invite, err := h.Auth.CreateInvite(r.Context(), userID, lifetime, scopeIDs...)
	if err != nil {
		if errors.Is(err, auth.ErrConflict) {
			http.Error(w, "invalid scope selection", http.StatusConflict)
			return
		}
		http.Error(w, "unable to create invite", http.StatusInternalServerError)
		return
	}
	activeScopes, err := h.Auth.ListActiveScopes(r.Context())
	if err != nil {
		http.Error(w, "unable to load scopes", http.StatusInternalServerError)
		return
	}
	selected := make(map[uuid.UUID]auth.Scope, len(activeScopes))
	for _, scope := range activeScopes {
		selected[scope.ID] = scope
	}
	selectedScopes := make([]auth.Scope, 0, len(scopeIDs))
	for _, id := range scopeIDs {
		if scope, ok := selected[id]; ok {
			selectedScopes = append(selectedScopes, scope)
		}
	}
	data := struct {
		Invite         auth.InviteResult
		SelectedScopes []auth.Scope
		CSRFToken      string
	}{Invite: invite, SelectedScopes: selectedScopes, CSRFToken: csrfFromRequest(r)}
	_ = inviteCreatedTemplate.Execute(w, data)
}

func (h AdminHandlers) RemoveInvite(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := h.Auth.RemoveInvite(r.Context(), id); errors.Is(err, auth.ErrConflict) {
		http.Error(w, "invite cannot be removed", http.StatusConflict)
		return
	} else if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/invites", http.StatusFound)
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

var devicesTemplate = template.Must(template.New("devices").Parse(`<!doctype html><title>Devices</title><link rel="stylesheet" href="/static/app.css"><h1>Devices</h1><nav><a href="/admin/invites">Invites</a> <a href="/admin/scopes">Scopes</a> <a href="/admin/docs">API docs</a></nav><table><tr><th>ID</th><th>User</th><th>Status</th><th>Scopes</th><th>Action</th></tr>{{range .Devices}}<tr><td>{{.ID}}</td><td>{{.UserID}}</td><td>{{.Status}}</td><td>{{range .Scopes}}{{.Name}} {{end}}</td><td><a href="/admin/devices/{{.ID}}/scopes">Edit scopes</a> {{if eq .Status "pending"}}<form method="post" action="/admin/devices/{{.ID}}/approve"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><button>Approve</button></form>{{else if eq .Status "approved"}}<form method="post" action="/admin/devices/{{.ID}}/revoke"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><button>Revoke</button></form>{{end}}</td></tr>{{end}}</table><form method="post" action="/admin/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button>Logout</button></form>`))
var invitesTemplate = template.Must(template.New("invites").Parse(`<!doctype html><title>Invites</title><link rel="stylesheet" href="/static/app.css"><script src="/static/uuid.js" defer></script><h1>Invites</h1><nav><a href="/admin/devices">Devices</a> <a href="/admin/scopes">Scopes</a> <a href="/admin/docs">API docs</a></nav><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>User UUID <input id="invite-user-id" name="user_id" required></label><button type="button" id="generate-user-id">Generate UUID</button><fieldset><legend>Scopes</legend>{{range .ActiveScopes}}<label><input type="checkbox" name="scope_id" value="{{.ID}}"> {{.Name}}</label>{{else}}<p>No active scopes</p>{{end}}</fieldset><button>Generate invite</button></form><table><tr><th>Prefix</th><th>User</th><th>Scopes</th><th>Expires</th><th>Used</th><th>Action</th></tr>{{range .Invites}}<tr><td>{{.Prefix}}</td><td>{{.UserID}}</td><td>{{range .Scopes}}{{.Name}} {{end}}</td><td>{{.ExpiresAt}}</td><td>{{.UsedAt}}</td><td>{{if not .UsedAt}}<form method="post" action="/admin/invites/{{.ID}}/remove"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><button>Remove</button></form>{{end}}</td></tr>{{end}}</table>`))
var inviteCreatedTemplate = template.Must(template.New("invite-created").Parse(`<!doctype html><title>Invite created</title><h1>Invite created</h1><p>Copy this token now. It cannot be retrieved later:</p><textarea readonly rows="3" cols="64">{{.Invite.Token}}</textarea><p>Scopes: {{range .SelectedScopes}}{{.Name}} {{else}}none{{end}}</p><p>Prefix: {{.Invite.Prefix}} — expires: {{.Invite.ExpiresAt}}</p><a href="/admin/invites">Back</a>`))
var scopesTemplate = template.Must(template.New("scopes").Parse(`<!doctype html><title>Scopes</title><link rel="stylesheet" href="/static/app.css"><h1>Scopes</h1><nav><a href="/admin/devices">Devices</a> <a href="/admin/invites">Invites</a> <a href="/admin/docs">API docs</a></nav><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>Scope name <input name="name" required pattern="[^\s]+"></label><button>Add scope</button></form><table><tr><th>Name</th><th>Status</th><th>Action</th></tr>{{range .Scopes}}<tr><td>{{.Name}}</td><td>{{if .DisabledAt}}Disabled{{else}}Active{{end}}</td><td>{{if .DisabledAt}}<form method="post" action="/admin/scopes/{{.ID}}/enable"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><button>Enable</button></form>{{else}}<form method="post" action="/admin/scopes/{{.ID}}/disable"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><button>Disable</button></form>{{end}}</td></tr>{{end}}</table>`))
var deviceScopesTemplate = template.Must(template.New("device-scopes").Parse(`<!doctype html><title>Device scopes</title><link rel="stylesheet" href="/static/app.css"><h1>Device scopes</h1><p>Device: {{.Device.ID}} — User: {{.Device.UserID}}</p>{{if .RetainedDisabled}}<p>Disabled assignments are retained and omitted from newly issued JWTs:</p><ul>{{range .RetainedDisabled}}<li>{{.Name}}</li>{{end}}</ul>{{end}}<form method="post"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}">{{range .ActiveScopes}}{{$scopeID := .ID}}<label><input type="checkbox" name="scope_id" value="{{.ID}}"{{range $.Device.Scopes}}{{if eq .ID $scopeID}} checked{{end}}{{end}}> {{.Name}}</label>{{end}}<button>Save scopes</button></form><p><a href="/admin/devices">Back to devices</a></p>`))

func (h AdminHandlers) Scopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := h.Auth.ListScopes(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	_ = scopesTemplate.Execute(w, struct {
		Scopes    []auth.Scope
		CSRFToken string
	}{Scopes: scopes, CSRFToken: csrfFromRequest(r)})
}

func (h AdminHandlers) CreateScope(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Auth.CreateScope(r.Context(), r.FormValue("name")); err != nil {
		if errors.Is(err, auth.ErrConflict) {
			http.Error(w, "scope already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin/scopes", http.StatusFound)
}

func (h AdminHandlers) ToggleScope(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	action := chi.URLParam(r, "action")
	switch action {
	case "disable":
		err = h.Auth.DisableScope(r.Context(), id)
	case "enable":
		err = h.Auth.EnableScope(r.Context(), id)
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "unable to update scope", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/scopes", http.StatusFound)
}

func (h AdminHandlers) DeviceScopes(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	devices, err := h.Auth.ListDevices(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var device *auth.Device
	for index := range devices {
		if devices[index].ID == id {
			device = &devices[index]
			break
		}
	}
	if device == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	activeScopes, err := h.Auth.ListActiveScopes(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	retainedDisabled := make([]auth.Scope, 0)
	for _, scope := range device.Scopes {
		if scope.DisabledAt != nil {
			retainedDisabled = append(retainedDisabled, scope)
		}
	}
	_ = deviceScopesTemplate.Execute(w, struct {
		Device           auth.Device
		ActiveScopes     []auth.Scope
		RetainedDisabled []auth.Scope
		CSRFToken        string
	}{Device: *device, ActiveScopes: activeScopes, RetainedDisabled: retainedDisabled, CSRFToken: csrfFromRequest(r)})
}

func (h AdminHandlers) ReplaceDeviceScopes(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var device *auth.Device
	devices, err := h.Auth.ListDevices(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	for index := range devices {
		if devices[index].ID == id {
			device = &devices[index]
			break
		}
	}
	if device == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	var scopeIDs []uuid.UUID
	for _, rawID := range r.Form["scope_id"] {
		scopeID, err := uuid.Parse(rawID)
		if err != nil {
			http.Error(w, "invalid scope", http.StatusBadRequest)
			return
		}
		scopeIDs = append(scopeIDs, scopeID)
	}
	for _, scope := range device.Scopes {
		if scope.DisabledAt != nil {
			scopeIDs = append(scopeIDs, scope.ID)
		}
	}
	if err := h.Auth.ReplaceDeviceScopes(r.Context(), id, scopeIDs); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "unable to update device scopes", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin/devices", http.StatusFound)
}
