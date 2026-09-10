window.ui = SwaggerUIBundle({
  url: "/admin/docs/openapi.yaml",
  dom_id: "#swagger-ui",
  deepLinking: false,
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
  layout: "StandaloneLayout"
});
