.PHONY: generate build test verify migrate

generate:
	templ generate
	sqlc generate

build: generate
	go build -trimpath -o bin/server ./cmd/server

test:
	go test ./...

integration:
	go test ./internal/integration -v

verify: generate
	go test ./...
	go test -race ./internal/auth ./internal/admin ./internal/web
	go vet ./...

migrate: build
	./bin/server migrate
