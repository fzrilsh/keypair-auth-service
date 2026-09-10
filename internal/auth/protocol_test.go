package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCanonicalMessageIsDeterministic(t *testing.T) {
	id := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	nonce := bytes.Repeat([]byte{0x42}, 32)
	got := CanonicalMessage(id, nonce, 123456789)
	if len(got) != len(domain)+16+32+8 {
		t.Fatalf("unexpected message length: %d", len(got))
	}
	if !bytes.HasPrefix(got, []byte(domain)) {
		t.Fatalf("message missing domain separator")
	}
	if bytes.Equal(got, CanonicalMessage(id, nonce, 123456790)) {
		t.Fatal("timestamp did not affect message")
	}
}

func TestDecodeKeysEnforcesLengths(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	encoded := base64.RawURLEncoding.EncodeToString(public)
	got, err := DecodePublicKey(encoded)
	if err != nil || !bytes.Equal(got, public) {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if _, err := DecodePublicKey(base64.RawURLEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected short public key to fail")
	}
	if _, err := DecodeSignature(base64.RawURLEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected short signature to fail")
	}
}

func TestGenerateInviteToken(t *testing.T) {
	plain, hash, prefix, err := GenerateInviteToken()
	if err != nil {
		t.Fatalf("GenerateInviteToken: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(plain)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("unexpected token: err=%v len=%d", err, len(decoded))
	}
	if len(hash) != 32 || prefix == "" || prefix == plain {
		t.Fatalf("unexpected token metadata")
	}
	if time.Now().IsZero() {
		t.Fatal("unreachable")
	}
}
