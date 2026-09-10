package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePEM(t *testing.T, block *pem.Block) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSigningKeysAndJWKS(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := writePEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	previousPath := writePEM(t, &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	keys, err := LoadSigningKeys(privatePath, "active", previousPath, "previous")
	if err != nil {
		t.Fatal(err)
	}
	if keys.ActiveKID != "active" || keys.PreviousKID != "previous" || len(keys.ActivePrivate) != ed25519.PrivateKeySize {
		t.Fatalf("unexpected keys: %+v", keys)
	}
	jwks := keys.JWKS()
	if len(jwks.Keys) != 2 || jwks.Keys[0].KID != "active" || jwks.Keys[1].KID != "previous" {
		t.Fatalf("unexpected JWKS: %+v", jwks)
	}
	if strings.Contains(string(jwks.Keys[0].X), "PRIVATE") {
		t.Fatal("JWKS contains private material")
	}
}

func TestLoadSigningKeysRejectsMalformedPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKeys(path, "active", "", ""); err == nil {
		t.Fatal("expected malformed PEM error")
	}
}

func TestLoadSigningKeysRejectsInvalidRotationConfiguration(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	activePath := writePEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := LoadSigningKeys(activePath, "", "", ""); err == nil {
		t.Fatal("expected empty active key id rejection")
	}
	if _, err := LoadSigningKeys(activePath, "active", "", "previous"); err == nil {
		t.Fatal("expected previous key id without file rejection")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	previousPath := writePEM(t, &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if _, err := LoadSigningKeys(activePath, "same", previousPath, "same"); err == nil {
		t.Fatal("expected duplicate key id rejection")
	}
}

func TestJWKSHasOnlyPublicFields(t *testing.T) {
	keys := testSigningKeys(t)
	encoded, err := keys.JWKSJSON()
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, item := range document["keys"].([]any) {
		fields := item.(map[string]any)
		for field := range fields {
			switch field {
			case "kty", "crv", "x", "use", "alg", "kid":
			default:
				t.Fatalf("unexpected JWKS field %q", field)
			}
		}
	}
}
