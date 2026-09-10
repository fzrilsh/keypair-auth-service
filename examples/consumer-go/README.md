# Go consumer example

This example verifies a device JWT locally using the auth service's public JWKS. It validates the EdDSA algorithm, `kid`, issuer, exact audience, and expiry through `internal/auth.ConsumerVerifier`.

Run from the module root with:

```sh
AUTH_SERVICE_URL=https://auth.example.internal \
AUTH_ISSUER=https://auth.example.internal \
AUTH_CLIENT_ID=app-a \
DEVICE_ACCESS_TOKEN='<token supplied by the device flow>' \
go run ./examples/consumer-go
```

The device flow is: generate an Ed25519 keypair locally, enroll only the public key with an invite token, request `/api/auth/challenge?device_id=...`, sign the canonical challenge payload with the private key, then POST `device_id`, `client_id`, optional `scope`, `signature`, and `timestamp` to `/api/auth/verify`. The requested scope is copied into the signed JWT and must be authorized by the consumer application; omitting it is valid. Private keys stay in platform secure storage and are never sent to this service.

The verifier refreshes JWKS when it sees an unknown `kid`, allowing a controlled key rotation. Consumers should use a cache age no longer than the service's advertised policy and keep the previous key available during the overlap window.
