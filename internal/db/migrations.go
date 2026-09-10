package db

import "embed"

// Migrations contains the goose SQL migrations bundled into the server binary.
//
//go:embed migrations/*.sql
var Migrations embed.FS
