package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

type JWKSFetcher interface {
	Fetch(context.Context) (SigningKeys, error)
}

type HTTPJWKSFetcher struct {
	URL    string
	Client *http.Client
}

func (f *HTTPJWKSFetcher) Fetch(ctx context.Context) (SigningKeys, error) {
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return SigningKeys{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return SigningKeys{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SigningKeys{}, fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}
	contentType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return SigningKeys{}, fmt.Errorf("JWKS content type must be application/json")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return SigningKeys{}, err
	}
	if len(body) > 1<<20 {
		return SigningKeys{}, fmt.Errorf("JWKS response too large")
	}
	var document JWKS
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return SigningKeys{}, err
	}
	return signingKeysFromJWKS(document)
}

func signingKeysFromJWKS(document JWKS) (SigningKeys, error) {
	if len(document.Keys) == 0 || len(document.Keys) > 2 {
		return SigningKeys{}, fmt.Errorf("JWKS must contain one or two keys")
	}
	var keys SigningKeys
	seen := make(map[string]struct{}, len(document.Keys))
	for index, item := range document.Keys {
		if item.KID == "" {
			return SigningKeys{}, fmt.Errorf("JWKS key id is required")
		}
		if _, ok := seen[item.KID]; ok {
			return SigningKeys{}, fmt.Errorf("JWKS contains duplicate key id")
		}
		seen[item.KID] = struct{}{}
		if item.Kty != "OKP" || item.Crv != "Ed25519" || item.Alg != "EdDSA" || item.Use != "sig" {
			return SigningKeys{}, fmt.Errorf("unsupported JWKS key")
		}
		decoded, err := decodePublicKey(item.X)
		if err != nil {
			return SigningKeys{}, err
		}
		if index == 0 {
			keys.ActivePublic, keys.ActiveKID = ed25519.PublicKey(decoded), item.KID
		} else {
			keys.PreviousPublic, keys.PreviousKID = ed25519.PublicKey(decoded), item.KID
		}
	}
	return keys, nil
}

func decodePublicKey(encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("invalid JWKS public key")
	}
	return decoded, nil
}

type ConsumerVerifier struct {
	Issuer      string
	Audience    string
	Fetcher     JWKSFetcher
	CacheMaxAge time.Duration
	mu          sync.Mutex
	keys        SigningKeys
	cachedAt    time.Time
}

func (v *ConsumerVerifier) Verify(ctx context.Context, raw string, now time.Time) (*Claims, error) {
	if v.Fetcher == nil || v.Issuer == "" || v.Audience == "" {
		return nil, fmt.Errorf("invalid consumer verifier configuration")
	}
	keys, err := v.getKeys(ctx, false, now)
	if err != nil {
		return nil, err
	}
	kid, kidErr := tokenKeyID(raw)
	if kidErr != nil {
		return nil, kidErr
	}
	if _, ok := keys.PublicKey(kid); !ok {
		keys, err = v.getKeys(ctx, true, now)
		if err != nil {
			return nil, err
		}
	}
	return ParseAndValidateJWT(keys, v.Issuer, v.Audience, raw, now)
}

func tokenKeyID(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid token")
	}
	var value struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(header, &value); err != nil || value.KID == "" {
		return "", fmt.Errorf("invalid token key id")
	}
	return value.KID, nil
}

func (v *ConsumerVerifier) getKeys(ctx context.Context, force bool, now time.Time) (SigningKeys, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !force && v.keys.ActiveKID != "" && now.Sub(v.cachedAt) < v.CacheMaxAge {
		return v.keys, nil
	}
	keys, err := v.Fetcher.Fetch(ctx)
	if err != nil {
		return SigningKeys{}, err
	}
	v.keys, v.cachedAt = keys, now
	return keys, nil
}
