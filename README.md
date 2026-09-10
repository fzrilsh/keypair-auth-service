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
- `POST /api/auth/verify`: submit the device signature and `client_id`, optionally including an opaque space-delimited `scope`; receives a 15-minute Bearer JWT with that scope claim
- `GET /.well-known/jwks.json`: public active/previous Ed25519 keys; no admin session required
- `/admin/*`: browser session-protected device and invite administration
- `/admin/docs`: session-protected Swagger UI and OpenAPI YAML

## Scope pada JWT

Endpoint `/api/auth/verify` mendukung optional OAuth-style `scope` per token. Scope dikirim oleh consumer saat meminta token dan diteruskan ke JWT yang diterbitkan service.

### Kontrak request

Contoh request verify dengan scope:

```json
{
  "device_id": "11111111-1111-4111-8111-111111111111",
  "client_id": "app-a",
  "scope": "profile:read devices:read",
  "signature": "<base64url-ed25519-signature>",
  "timestamp": 1760000000
}
```

Field `scope` adalah string optional dan menggunakan format space-delimited. Satu request dapat meminta satu atau beberapa scope, misalnya:

```text
profile:read
profile:read devices:read
billing:read billing:write
```

Service tidak memiliki daftar scope, tidak melakukan normalisasi, tidak mengartikan nama scope, dan tidak menyimpan scope ke database. Nilainya diteruskan apa adanya ke token. `client_id` tetap wajib terdaftar di `ALLOWED_CLIENT_IDS`; scope tidak menggantikan validasi audience tersebut.

### Alur implementasi

1. Consumer membuat request challenge dan device menandatangani canonical message seperti biasa:
   `keypair-auth/v1 || device UUID bytes || nonce bytes || timestamp (big-endian int64)`.
2. Consumer mengirim signature, `client_id`, dan optional `scope` ke `/api/auth/verify`.
3. Auth service memvalidasi device signature, timestamp, nonce, status device, dan allowlist `client_id` seperti sebelumnya.
4. Jika valid, service memasukkan scope ke claim JWT `scope` lalu menandatangani token dengan EdDSA.
5. Consumer mengambil JWKS dan memvalidasi signature JWT, `kid`, issuer, audience, waktu berlaku, lalu menerapkan policy scope miliknya sendiri.

Scope **tidak dimasukkan ke canonical device signature**. Ini sengaja dipertahankan agar client device lama tetap kompatibel dan agar perubahan scope hanya memengaruhi token yang diterbitkan, bukan protocol challenge-response.

### JWT yang dihasilkan

Jika request berisi `scope: "profile:read devices:read"`, payload JWT akan memiliki claim seperti berikut:

```json
{
  "iss": "https://auth.example.internal",
  "sub": "<device-id>",
  "aud": ["app-a"],
  "scope": "profile:read devices:read",
  "device_id": "<device-id>",
  "user_id": "<user-id>",
  "iat": 1760000000,
  "exp": 1760000900
}
```

The JWT header contains `alg: "EdDSA"` and a `kid` value used to select the public key from JWKS. `scope` berada di dalam JWT yang ditandatangani, sehingga consumer dapat memastikan nilainya tidak diubah setelah token diterbitkan. Namun, scope tetap merupakan request dari pihak yang memiliki private key device; auth service tidak menyatakan bahwa scope tersebut memiliki izin tertentu.

Jika `scope` tidak dikirim atau nilainya kosong, request tetap valid dan claim `scope` tidak ditulis ke JWT. Token lama tanpa scope tetap valid untuk consumer yang hanya memerlukan audience dan claim standar.

### Policy di consumer

Karena auth service hanya meneruskan scope, setiap consumer harus menentukan scope yang boleh digunakan oleh aplikasinya. Contoh policy sederhana:

```text
app-a: profile:read, devices:read
app-b: billing:read
```

Consumer sebaiknya:

- memvalidasi JWT secara cryptographic menggunakan JWKS, bukan hanya decode payload;
- memvalidasi exact `aud` sebelum membaca scope;
- membaca scope dengan pemisah spasi, misalnya `strings.Fields(claims.Scope)` di Go;
- menolak token jika scope wajib tidak ada atau ada scope yang tidak dikenal oleh policy consumer;
- tidak memberikan akses hanya karena scope tertulis di token tanpa membandingkannya dengan policy lokal.

Contoh pemeriksaan di consumer Go:

```go
claims, err := verifier.Verify(ctx, rawToken, time.Now())
if err != nil {
    return err
}

allowed := map[string]bool{
    "profile:read": true,
    "devices:read": true,
}
for _, requested := range strings.Fields(claims.Scope) {
    if !allowed[requested] {
        return fmt.Errorf("scope is not allowed: %s", requested)
    }
}
```

Tidak ada field `scope` tambahan di response JSON token. Scope hanya tersedia sebagai claim di `access_token`; consumer harus memvalidasi dan membaca claim tersebut setelah token berhasil diverifikasi.

### Lokasi implementasi

- `internal/web/api_handlers.go`: menerima `scope` dari JSON `/api/auth/verify`.
- `internal/auth/verify.go`: meneruskan scope ke proses penerbitan token.
- `internal/auth/jwt.go`: mendefinisikan claim `scope` dan menerbitkan JWT scoped.
- `internal/web/docs/openapi.yaml`: kontrak OpenAPI untuk request verify.
- `examples/consumer-http/README.md`: contoh request HTTP.
- `examples/consumer-go/README.md`: alur consumer Go dan validasi token.

Consumers must validate `alg=EdDSA`, `kid`, issuer, exact audience, `iat`, and `exp` locally using JWKS, then enforce their own scope policy. On rotation, retain the previous public key through the maximum token lifetime plus JWKS cache age, then remove it only after that overlap.

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