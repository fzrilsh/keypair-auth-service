package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"
)

const domain = "keypair-auth/v1"

func CanonicalMessage(deviceID uuid.UUID, nonce []byte, timestamp int64) []byte {
	message := make([]byte, 0, len(domain)+16+len(nonce)+8)
	message = append(message, domain...)
	message = append(message, deviceID[:]...)
	message = append(message, nonce...)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(timestamp))
	return append(message, encoded[:]...)
}

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func DecodeSignature(encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature")
	}
	return decoded, nil
}

func GenerateInviteToken() (string, []byte, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, "", err
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(plain))
	prefix := plain
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return plain, digest[:], prefix, nil
}
