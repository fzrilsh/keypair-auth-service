# HTTP-only consumer integration

Public signing metadata is available without an admin session:

```sh
curl --fail https://auth.example.internal/.well-known/jwks.json
```

A consumer device obtains a challenge and signs the canonical payload locally:

```sh
curl --fail 'https://auth.example.internal/api/auth/challenge?device_id=<uuid>'
# sign: keypair-auth/v1 || device UUID bytes || nonce bytes || timestamp (big-endian int64)
curl --fail -X POST https://auth.example.internal/api/auth/verify \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"<uuid>","client_id":"app-a","signature":"<base64url-signature>","timestamp":<unix-seconds>}'
```

The verify request does not contain a `scope` field. An administrator creates scope names in the catalog, selects scopes on the invite, and can edit the enrolled device's assignments in `/admin/devices/<device-id>/scopes`. The service copies invite scopes to the device during enrollment and includes only active assigned names in newly issued JWTs. Sending a client-supplied `scope` is rejected as an invalid request. A device with no active assignment receives a token without the `scope` claim.

The response contains a short-lived Bearer JWT. The consuming app must verify it locally before accepting it: require `alg=EdDSA`, resolve `kid` from the JWKS, validate the configured issuer, validate the exact `aud` value (`app-a` in this example), and enforce `exp`/`iat`. Do not trust a JWT merely because it is structurally decodable, and do not put private device keys in HTTP requests, logs, images, or environment examples.

During signing-key rotation the JWKS may contain the active public key and the previous public key. Cache responses for no longer than `Cache-Control: public, max-age=N`; refetch once when an unknown `kid` is encountered, then reject the token if the key is still unavailable.
