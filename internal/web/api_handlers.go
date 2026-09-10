package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"keypair-auth-service/internal/auth"
	"keypair-auth-service/internal/httputil"
)

type APIHandlers struct {
	Auth             *auth.Service
	RequestBodyLimit int64
}

type enrollRequest struct {
	InviteToken string `json:"invite_token"`
	PublicKey   string `json:"public_key"`
	DeviceName  string `json:"device_name"`
}

type verifyRequest struct {
	DeviceID  string `json:"device_id"`
	ClientID  string `json:"client_id"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

func (h APIHandlers) Enroll(w http.ResponseWriter, r *http.Request) {
	var input enrollRequest
	if err := httputil.DecodeJSON(w, r, h.limit(), &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "request payload is invalid")
		return
	}
	publicKey, err := auth.DecodePublicKey(input.PublicKey)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "request payload is invalid")
		return
	}
	result, err := h.Auth.Enroll(r.Context(), auth.EnrollmentInput{InviteToken: input.InviteToken, PublicKey: publicKey, DeviceName: input.DeviceName})
	if err != nil {
		h.writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"device_id": result.DeviceID.String(), "status": result.Status})
}

func (h APIHandlers) Challenge(w http.ResponseWriter, r *http.Request) {
	deviceID, err := uuid.Parse(r.URL.Query().Get("device_id"))
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "device not found")
		return
	}
	result, err := h.Auth.Challenge(r.Context(), deviceID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "device not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_id": result.DeviceID.String(), "nonce": base64.RawURLEncoding.EncodeToString(result.Nonce), "expires_at": result.ExpiresAt.UTC().Format(time.RFC3339)})
}

func (h APIHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	var input verifyRequest
	if err := httputil.DecodeJSON(w, r, h.limit(), &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "request payload is invalid")
		return
	}
	deviceID, err := uuid.Parse(input.DeviceID)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "invalid_credential", "authentication failed")
		return
	}
	signature, err := auth.DecodeSignature(input.Signature)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "invalid_credential", "authentication failed")
		return
	}
	result, err := h.Auth.Verify(r.Context(), auth.VerifyInput{DeviceID: deviceID, ClientID: input.ClientID, Signature: signature, Timestamp: input.Timestamp})
	if err != nil {
		h.writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h APIHandlers) limit() int64 {
	if h.RequestBodyLimit > 0 {
		return h.RequestBodyLimit
	}
	return 1 << 20
}

func (h APIHandlers) writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrConflict):
		writeAPIError(w, http.StatusConflict, "conflict", "resource conflict")
	case errors.Is(err, auth.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, auth.ErrInvalidCredential):
		writeAPIError(w, http.StatusUnauthorized, "invalid_credential", "authentication failed")
	default:
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	httputil.WriteJSONError(w, status, code, message)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func parseTimestamp(raw string) (int64, error) { return strconv.ParseInt(raw, 10, 64) }
