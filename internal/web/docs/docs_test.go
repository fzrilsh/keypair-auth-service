package docs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestSpecIsValidOpenAPI31(t *testing.T) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromData(Spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Validate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if document.OpenAPI != "3.1.0" {
		t.Fatalf("unexpected version %q", document.OpenAPI)
	}
}

func TestHandlerUsesSameOriginSpecAndNoStore(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/docs", nil)
	res := httptest.NewRecorder()
	Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status %d", res.Code)
	}
	body := res.Body.String()
	if !strings.Contains(body, `/admin/docs/assets/swagger-ui-init.js`) {
		t.Fatal("missing same-origin Swagger bootstrap URL")
	}
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatal("docs page contains remote URL")
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("expected no-store")
	}
}

func TestAssetHandlerServesEmbeddedSwaggerAsset(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/swagger-ui.css", nil)
	res := httptest.NewRecorder()
	AssetHandler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("unexpected asset response: %d %q", res.Code, res.Header().Get("Content-Type"))
	}
}

func TestSpecHandlerReturnsYaml(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/docs/openapi.yaml", nil)
	res := httptest.NewRecorder()
	SpecHandler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Header().Get("Content-Type"), "yaml") {
		t.Fatalf("unexpected response: %d %q", res.Code, res.Header().Get("Content-Type"))
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("expected no-store")
	}
}

func TestSpecDocumentsMultiAppJWTContract(t *testing.T) {
	for _, expected := range []string{"/.well-known/jwks.json", "client_id", "EdDSA", "DeviceBearer", "kid", "audience"} {
		if !strings.Contains(string(Spec), expected) {
			t.Fatalf("OpenAPI spec missing %q", expected)
		}
	}
}

func TestHandlerUsesExternalCSPCompatibleBootstrap(t *testing.T) {
	res := httptest.NewRecorder()
	Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/admin/docs", nil))
	body := res.Body.String()
	if !strings.Contains(body, "/admin/docs/assets/swagger-ui-init.js") {
		t.Fatal("missing external Swagger bootstrap asset")
	}
	if strings.Contains(body, "<script>window.ui") {
		t.Fatal("Swagger bootstrap must not be inline under the current CSP")
	}
	asset := httptest.NewRecorder()
	AssetHandler().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/swagger-ui-init.js", nil))
	if asset.Code != http.StatusOK || !strings.Contains(asset.Header().Get("Content-Type"), "javascript") || !strings.Contains(asset.Body.String(), "SwaggerUIBundle") {
		t.Fatalf("unexpected bootstrap asset response: %d %q", asset.Code, asset.Body.String())
	}
}
