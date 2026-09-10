package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func testSigningKeys(t *testing.T) SigningKeys {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return SigningKeys{ActivePrivate: private, ActivePublic: public, ActiveKID: "active"}
}

func TestIssueAndParseEdDSAJWT(t *testing.T) {
	keys := testSigningKeys(t)
	device := Device{ID: uuid.New(), UserID: uuid.New()}
	now := time.Unix(1000, 0)
	raw, err := IssueDeviceJWT(keys, "test-service", "app-a", device, 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseAndValidateJWT(keys, "test-service", "app-a", raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != device.ID.String() || claims.UserID != device.UserID.String() || claims.Issuer != "test-service" || len(claims.Audience) != 1 || claims.Audience[0] != "app-a" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestParseRejectsWrongAudienceAndUnknownKid(t *testing.T) {
	keys := testSigningKeys(t)
	device := Device{ID: uuid.New(), UserID: uuid.New()}
	raw, err := IssueDeviceJWT(keys, "test-service", "app-a", device, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndValidateJWT(keys, "test-service", "app-b", raw, time.Now()); err == nil {
		t.Fatal("expected wrong audience rejection")
	}
	keys.ActiveKID = "different"
	if _, err := ParseAndValidateJWT(keys, "test-service", "app-a", raw, time.Now()); err == nil {
		t.Fatal("expected unknown kid rejection")
	}
}

func TestVerifyIssuesEdDSAToken(t *testing.T) {
	service, store, private, deviceID := newTestService(t)
	service.cfg.Keys = testSigningKeys(t)
	service.cfg.AllowedAudiences = map[string]struct{}{"app-a": {}}
	if err := store.Approve(deviceID); err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Challenge(context.Background(), deviceID)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().Unix()
	signature := ed25519.Sign(private, CanonicalMessage(deviceID, challenge.Nonce, timestamp))
	result, err := service.Verify(context.Background(), VerifyInput{DeviceID: deviceID, ClientID: "app-a", Signature: signature, Timestamp: timestamp})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndValidateJWT(service.cfg.Keys, "test-service", "app-a", result.AccessToken, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestSigningKeyPEMFixtureCompiles(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}) == nil {
		t.Fatal("expected PEM")
	}
}

func TestParseRejectsHS256AndExpiredTokens(t *testing.T) {
	keys := testSigningKeys(t)
	device := Device{ID: uuid.New(), UserID: uuid.New()}
	hs256, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: "test-service", Audience: jwt.ClaimStrings{"app-a"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now()),
	}).SignedString([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndValidateJWT(keys, "test-service", "app-a", hs256, time.Now()); err == nil {
		t.Fatal("expected HS256 rejection")
	}
	expired, err := IssueDeviceJWT(keys, "test-service", "app-a", device, time.Minute, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndValidateJWT(keys, "test-service", "app-a", expired, time.Unix(200, 0)); err == nil {
		t.Fatal("expected expired token rejection")
	}
}

func TestUnknownClientDoesNotConsumeNonce(t *testing.T) {
	service, store, private, deviceID := newTestService(t)
	service.cfg.Keys = testSigningKeys(t)
	service.cfg.AllowedAudiences = map[string]struct{}{"app-a": {}}
	if err := store.Approve(deviceID); err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Challenge(context.Background(), deviceID)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().Unix()
	signature := ed25519.Sign(private, CanonicalMessage(deviceID, challenge.Nonce, timestamp))
	if _, err := service.Verify(context.Background(), VerifyInput{DeviceID: deviceID, ClientID: "unknown", Signature: signature, Timestamp: timestamp}); err == nil {
		t.Fatal("expected unknown client rejection")
	}
	again, err := service.Challenge(context.Background(), deviceID)
	if err != nil || string(again.Nonce) != string(challenge.Nonce) {
		t.Fatalf("expected nonce preservation, got %+v %v", again, err)
	}
}
