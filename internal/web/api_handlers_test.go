package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJSONErrorEnvelope(t *testing.T) {
	res := httptest.NewRecorder()
	writeAPIError(res, 401, "invalid_credential", "authentication failed")
	if res.Code != 401 || !strings.Contains(res.Body.String(), `"error"`) || !strings.Contains(res.Body.String(), "invalid_credential") {
		t.Fatalf("unexpected response: %d %s", res.Code, res.Body.String())
	}
}

func TestVerifyRejectsClientSuppliedScope(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/auth/verify", strings.NewReader(`{"device_id":"00000000-0000-0000-0000-000000000001","client_id":"app-a","scope":"admin","signature":"bad","timestamp":1}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	(APIHandlers{}).Verify(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid request, got %d: %s", response.Code, response.Body.String())
	}
}
