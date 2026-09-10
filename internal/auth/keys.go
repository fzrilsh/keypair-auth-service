package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

type SigningKeys struct {
	ActivePrivate  ed25519.PrivateKey
	ActivePublic   ed25519.PublicKey
	ActiveKID      string
	PreviousPublic ed25519.PublicKey
	PreviousKID    string
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
}

func LoadSigningKeys(activeFile, activeKID, previousFile, previousKID string) (SigningKeys, error) {
	if !validKID(activeKID) {
		return SigningKeys{}, fmt.Errorf("active signing key ID is invalid")
	}
	if previousFile == "" && previousKID != "" {
		return SigningKeys{}, fmt.Errorf("previous signing key ID requires a public key file")
	}
	if previousFile != "" && !validKID(previousKID) {
		return SigningKeys{}, fmt.Errorf("previous signing key ID is invalid")
	}
	if previousKID == activeKID && previousKID != "" {
		return SigningKeys{}, fmt.Errorf("active and previous signing key IDs must differ")
	}
	activeBytes, err := os.ReadFile(activeFile)
	if err != nil {
		return SigningKeys{}, fmt.Errorf("read active signing key: %w", err)
	}
	active, err := parsePrivateKey(activeBytes)
	if err != nil {
		return SigningKeys{}, fmt.Errorf("parse active signing key: %w", err)
	}
	keys := SigningKeys{ActivePrivate: active, ActivePublic: active.Public().(ed25519.PublicKey), ActiveKID: activeKID}
	if previousFile != "" {
		if previousKID == "" {
			return SigningKeys{}, fmt.Errorf("previous signing key ID is required")
		}
		previousBytes, err := os.ReadFile(previousFile)
		if err != nil {
			return SigningKeys{}, fmt.Errorf("read previous signing key: %w", err)
		}
		previous, err := parsePublicKey(previousBytes)
		if err != nil {
			return SigningKeys{}, fmt.Errorf("parse previous signing key: %w", err)
		}
		if previousKID == activeKID {
			return SigningKeys{}, fmt.Errorf("active and previous signing key IDs must differ")
		}
		keys.PreviousPublic, keys.PreviousKID = previous, previousKID
	}
	return keys, nil
}

func validKID(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func parsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("PEM block missing")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PKCS#8: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key is not Ed25519 private key")
	}
	return append(ed25519.PrivateKey(nil), private...), nil
}

func parsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("PEM block missing")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PKIX: %w", err)
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key is not Ed25519 public key")
	}
	return append(ed25519.PublicKey(nil), public...), nil
}

func (k SigningKeys) PublicKey(kid string) (ed25519.PublicKey, bool) {
	if kid == k.ActiveKID {
		return k.ActivePublic, true
	}
	if kid == k.PreviousKID && len(k.PreviousPublic) > 0 {
		return k.PreviousPublic, true
	}
	return nil, false
}

func (k SigningKeys) JWKS() JWKS {
	result := JWKS{Keys: []JWK{publicJWK(k.ActivePublic, k.ActiveKID)}}
	if len(k.PreviousPublic) > 0 {
		result.Keys = append(result.Keys, publicJWK(k.PreviousPublic, k.PreviousKID))
	}
	return result
}

func (k SigningKeys) JWKSJSON() ([]byte, error) { return json.Marshal(k.JWKS()) }

func publicJWK(public ed25519.PublicKey, kid string) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(public), Use: "sig", Alg: "EdDSA", KID: kid}
}
