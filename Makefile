.PHONY: generate build test verify migrate local-init local-up local-down

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

local-init:
	docker-compose run --rm key-init

local-up: local-init
	docker-compose up --build

local-down:
	docker-compose down
