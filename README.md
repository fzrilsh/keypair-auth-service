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
