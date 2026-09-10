package web

import (
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
