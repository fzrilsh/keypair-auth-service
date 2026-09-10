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

The device flow is: generate an Ed25519 keypair locally, enroll only the public key with an invite token, request `/api/auth/challenge?device_id=...`, sign the canonical challenge payload with the private key, then POST `device_id`, `client_id`, `signature`, and `timestamp` to `/api/auth/verify`. Scope is never supplied by the device or consumer: an administrator selects catalog scopes on the invite or edits the device assignment after enrollment. Newly issued JWTs contain the active assigned scopes, and the consumer application must authorize those claims against its own policy. Private keys stay in platform secure storage and are never sent to this service.

The verifier refreshes JWKS when it sees an unknown `kid`, allowing a controlled key rotation. Consumers should use a cache age no longer than the service's advertised policy and keep the previous key available during the overlap window.
