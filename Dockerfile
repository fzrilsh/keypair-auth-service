FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/server /server
USER nonroot:nonroot
EXPOSE 8080
# Runtime secret contract: mount the active private key read-only at
# /run/secrets/jwt-signing-private.pem and, during rotation, mount only the
# previous public key at /run/secrets/jwt-previous-public.pem. Never COPY keys
# into this image or pass private material through build arguments.
ENTRYPOINT ["/server", "serve"]
