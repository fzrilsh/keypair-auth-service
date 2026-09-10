package static

import "embed"

//go:embed app.css htmx.min.js uuid.js
var FS embed.FS
