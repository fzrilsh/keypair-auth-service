package docs

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed openapi.yaml
var Spec []byte

//go:embed static/*
var staticFS embed.FS

func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>API Documentation</title><link rel="stylesheet" href="/admin/docs/assets/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="/admin/docs/assets/swagger-ui-bundle.js"></script><script src="/admin/docs/assets/swagger-ui-standalone-preset.js"></script><script>window.ui = SwaggerUIBundle({url: "/admin/docs/openapi.yaml", dom_id: "#swagger-ui", deepLinking: false, presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset], layout: "StandaloneLayout"});</script></body></html>`))
	})
}

func SpecHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", "inline; filename=openapi.yaml")
		_, _ = w.Write(Spec)
	})
}

func AssetHandler() http.Handler {
	assets, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(assets))
}
