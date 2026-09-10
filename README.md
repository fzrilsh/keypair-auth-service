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

- `POST /api/devices/enroll`: consume a one-time invite and register a public key as pending; scopes selected on the invite are copied to the device
- `GET /api/auth/challenge?device_id=...`: obtain a one-time nonce for an approved device
- `POST /api/auth/verify`: submit the device signature and `client_id`; receives a 15-minute Bearer JWT whose scope claim is derived from the device's active admin assignments
- `GET /.well-known/jwks.json`: public active/previous Ed25519 keys; no admin session required
- `/admin/*`: browser session-protected scope catalog, device, and invite administration
- `/admin/docs`: session-protected Swagger UI and OpenAPI YAML

## Admin-managed device scopes

Scopes are authorization labels managed by administrators. They are global per `device_id`: the same active scope set is used whenever that device receives a token, regardless of the allowlisted `client_id` audience. The auth service does not accept scope from the client, device, or user during verification.

### Scope lifecycle

1. An administrator creates a unique scope name in `/admin/scopes`, such as `profile:read` or `devices:read`.
2. When creating an invite, the administrator selects zero or more active catalog scopes.
3. Enrollment copies the selected invite scopes to the new device.
4. After enrollment, the administrator can change the device assignment at `/admin/devices/{device_id}/scopes`.
5. During `/api/auth/verify`, the service loads the device assignment and places active scope names into the signed JWT `scope` claim as a space-delimited string.

The catalog supports disabling and re-enabling names instead of deleting them. Disabled scopes remain stored and assigned for auditability, but are omitted from newly issued JWTs. Existing JWTs are unchanged and remain valid until their normal expiration. A device with no active assignments receives a JWT without a `scope` claim.

### How to determine a device's scopes

There are two valid ways to determine the scope set for a device:

1. **Administrative assignment:** sign in to the admin panel, open `/admin/devices`, find the device by its `device_id`, and select **Edit scopes**. The page shows the active catalog scopes currently assigned to that device. Disabled assignments are also shown as retained assignments, but they are not included in newly issued JWTs. The invite list also shows the scopes selected when each invite was created.
2. **Runtime token:** after the device completes `/api/auth/challenge` and `/api/auth/verify`, the consumer validates the returned JWT using the public JWKS and reads the signed `scope` claim. This is the effective scope set at issuance time. The token response does not expose scope as a separate JSON field.

There is intentionally no public endpoint that lets a client query a device's scope assignments. Scope assignment is an admin concern; consumers learn the effective authorization context from a cryptographically validated JWT. If the device has no active scopes, the validated JWT has no `scope` claim.

### Verify request contract

The verify request contains no `scope` field:

```json
{
  "device_id": "11111111-1111-4111-8111-111111111111",
  "client_id": "app-a",
  "signature": "<base64url-ed25519-signature>",
  "timestamp": 1760000000
}
```

Because the JSON decoder rejects unknown fields, sending a client-supplied `scope` returns HTTP 400. `client_id` remains only the JWT audience selector and must be present in `ALLOWED_CLIENT_IDS`; it does not select or grant scopes.

### Implementation flow

1. An administrator creates or enables catalog scopes and assigns them through an invite or directly to a device.
2. The consumer requests a challenge and the device signs the canonical payload:
   `keypair-auth/v1 || device UUID bytes || nonce bytes || timestamp (big-endian int64)`.
3. The consumer sends the signature and `client_id` to `/api/auth/verify`; it sends no scope.
4. The auth service validates the device signature, timestamp, nonce, device status, and `client_id` allowlist.
5. If validation succeeds, the service reads active scopes assigned to the device, joins their names with spaces, and signs the result in the JWT `scope` claim.
6. The consumer fetches the JWKS, validates the JWT signature, `kid`, issuer, audience, and time claims, then applies its own permission policy.

The scope is **not included in the canonical device signature**. Scope assignment is an administrative data change and does not alter device-client signing compatibility. Device scope changes affect newly issued tokens; they do not retroactively modify existing tokens.

### Issued JWT

For a device assigned `profile:read` and `devices:read`, the JWT payload includes claims such as:

```json
{
  "iss": "https://auth.example.internal",
  "sub": "<device-id>",
  "aud": ["app-a"],
  "scope": "devices:read profile:read",
  "device_id": "<device-id>",
  "user_id": "<user-id>",
  "iat": 1760000000,
  "exp": 1760000900
}
```

The JWT header contains `alg: "EdDSA"` and a `kid` value used to select the public key from JWKS. The `scope` claim is inside the signed JWT, so a consumer can verify that the administrator-assigned values were not modified after issuance.

### Consumer policy

The auth service assigns scope values but does not know the permissions represented by an individual consumer application. Each consumer must define which assigned scopes it accepts. For example:

```text
app-a: profile:read, devices:read
app-b: billing:read
```

Consumers should:

- validate the JWT cryptographically using JWKS rather than only decoding the payload;
- validate the exact `aud` before reading scope;
- read scope as space-delimited values, for example with `strings.Fields(claims.Scope)` in Go;
- reject a token when a required scope is missing or an unknown scope is present in the consumer's policy;
- never grant access merely because a scope appears in the token without comparing it with local policy.

Example scope enforcement in a Go consumer:

```go
claims, err := verifier.Verify(ctx, rawToken, time.Now())
if err != nil {
    return err
}

allowed := map[string]bool{
    "profile:read": true,
    "devices:read": true,
}
for _, assigned := range strings.Fields(claims.Scope) {
    if !allowed[assigned] {
        return fmt.Errorf("scope is not allowed: %s", assigned)
    }
}
```

The token response JSON does not contain a separate `scope` field. Scope is available only as a claim inside `access_token`; the consumer must validate the token before reading that claim.

### Implementation locations

- `internal/web/admin_handlers.go`: manages the catalog, invite selections, and device assignments.
- `internal/auth/management.go`: validates scope names and manages assignments.
- `internal/auth/verify.go`: loads active device scopes and passes them to token issuance.
- `internal/auth/jwt.go`: defines the signed JWT `scope` claim.
- `internal/db/migrations/00003_scopes.sql`: stores the catalog, invite assignments, and device assignments.
- `internal/web/docs/openapi.yaml`: defines the verify request without a client-supplied scope.
- `examples/consumer-http/README.md`: provides the HTTP device flow.
- `examples/consumer-go/README.md`: documents local token validation.

Consumers must validate `alg=EdDSA`, `kid`, issuer, exact audience, `iat`, and `exp` locally using JWKS, then enforce their local permission policy. On rotation, retain the previous public key through the maximum token lifetime plus JWKS cache age, then remove it only after that overlap window.

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
