# Keypair Auth Service

Standalone Go service for device enrollment and Ed25519 challenge-response authentication. The service is the source of truth for approved device public keys and issues short-lived EdDSA JWTs bound to an allowlisted consumer application through `aud`.

## Runtime configuration

Required environment variables:

- `DATABASE_URL`
- `JWT_SIGNING_PRIVATE_KEY_FILE`: PKCS#8 Ed25519 private-key PEM, mounted read-only as a runtime secret
- `JWT_SIGNING_KEY_ID`: stable safe `kid` value
- `ALLOWED_CLIENT_IDS`: comma-separated allowlist, for example `app-a,app-b`
- `ADMIN_SESSION_SECRET`: at least 32 random bytes

Optional values include `JWT_ISSUER`, `JWKS_CACHE_MAX_AGE` (default `5m` and shorter than `JWT_LIFETIME`), `JWT_PREVIOUS_PUBLIC_KEY_FILE`, `JWT_PREVIOUS_KEY_ID`, and the existing TTL/listener settings. See `.env.example` for a safe template.

Generate a local development key without checking it into the repository:

```sh
openssl genpkey -algorithm ED25519 -out /tmp/jwt-signing-private.pem
openssl pkey -in /tmp/jwt-signing-private.pem -pubout -out /tmp/jwt-signing-public.pem
```

The previous file is a public PKIX PEM and the active file is a private PKCS#8 PEM. Never put either private material or real credentials in Docker build arguments, logs, examples, or source control.

## Endpoints

- `POST /api/devices/enroll`: consume a one-time invite and register a public key as pending
- `GET /api/auth/challenge?device_id=...`: obtain a one-time nonce for an approved device
- `POST /api/auth/verify`: submit the device signature and `client_id`, receiving a 15-minute Bearer JWT
- `GET /.well-known/jwks.json`: public active/previous Ed25519 keys; no admin session required
- `/admin/*`: browser session-protected device and invite administration
- `/admin/docs`: session-protected Swagger UI and OpenAPI YAML

Consumers must validate `alg=EdDSA`, `kid`, issuer, exact audience, `iat`, and `exp` locally using JWKS. On rotation, retain the previous public key through the maximum token lifetime plus JWKS cache age, then remove it only after that overlap.

## Development

```sh
make generate
make test
make verify
make build
```

`migrate` and `bootstrap-admin` require only `DATABASE_URL` because they do not issue device tokens. PostgreSQL-backed concurrency and end-to-end checks should use a disposable database, never a developer or production database.

## Local Docker Compose

Prerequisites: Docker Desktop (or Docker Engine) with the Compose v2 command `docker-compose`.

Initialize a disposable signing key inside a local Docker volume and start PostgreSQL, migrations, and the API:

```sh
make local-init
docker-compose up --build
```

The API is available at `http://localhost:8080`. In another terminal, verify the service and public JWKS endpoint:

```sh
curl -f http://localhost:8080/readyz
curl -f http://localhost:8080/.well-known/jwks.json
```

The Compose stack uses PostgreSQL service `postgres`, generates the local Ed25519 key in the ignored Docker volume `jwtkeys`, runs migrations once through the `migrate` service, and starts `app` only after key initialization and migration succeed. The app mounts the key volume read-only. The key never enters the image, host repository, or Git history.

The production deployment workflow compiles a static Linux `amd64` `bin/server` binary on GitHub Actions, syncs that artifact together with `Dockerfile.runtime` to the VPS, and builds only the small distroless runtime image there. The VPS does not install Go or compile the application. Its infrastructure Compose file at `/home/deploy/infra` must use the image tag produced by the workflow, rather than Compose's generated project tag:

```yaml
services:
  keypair-auth:
    build: /home/deploy/services/keypair-auth
    image: keypair-auth:latest
    restart: unless-stopped
```

The workflow checks this declaration and fails before migration if the image tag is missing or different. Configure `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`, and `VPS_FINGERPRINT` in GitHub Actions secrets. The remote deployment path and Compose service name must match the workflow.

Create the first local admin after the stack is running. Use a throwaway local password only:

```sh
printf '%s\n' 'local-admin-password-change-me' | \
  docker-compose exec -T app /server bootstrap-admin \
  --email admin@example.test --password-stdin
```

Stop the stack while keeping the PostgreSQL volume:

```sh
make local-down
```

To reset the disposable database completely, use the destructive command below only for local testing:

```sh
docker-compose down -v
```

Override local defaults through an ignored `.env` file or shell environment, for example `HTTP_PORT`, `POSTGRES_PASSWORD`, `ADMIN_SESSION_SECRET`, `ALLOWED_CLIENT_IDS`, and `JWT_ISSUER`. Do not use these local defaults in production. To recreate the disposable signing key, remove the key volume with `docker-compose down -v` before starting the stack again.

## VPS Docker maintenance

The deploy workflow compiles the application on GitHub and builds only the small distroless runtime image on the VPS. BuildKit cache is separate from dangling image cleanup. On the VPS, schedule a weekly maintenance task during a window with no deployment in progress:

```cron
0 3 * * 0 docker builder prune -f --filter "until=168h" >> /home/deploy/logs/docker-prune.log 2>&1
```

Create `/home/deploy/logs` first and ensure the cron user has permission to access Docker. This command removes only BuildKit cache older than seven days; it does not replace the post-deploy `docker image prune -f` step.