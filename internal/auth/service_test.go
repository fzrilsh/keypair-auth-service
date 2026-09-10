package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestService(t *testing.T) (*Service, *MemoryStore, ed25519.PrivateKey, uuid.UUID) {
	t.Helper()
	store := NewMemoryStore()
	service := NewService(store, ServiceConfig{
		Issuer:        "test-service",
		NonceTTL:      time.Minute,
		TimestampSkew: time.Minute,
		JWTLifetime:   15 * time.Minute,
	})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	token, hash, prefix, err := GenerateInviteToken()
	if err != nil {
		t.Fatal(err)
	}
	store.AddInvite(hash, prefix, userID, time.Now().Add(time.Minute))
	result, err := service.Enroll(context.Background(), EnrollmentInput{InviteToken: token, PublicKey: public, DeviceName: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, private, result.DeviceID
}

func TestEnrollConsumesInviteAndCreatesPendingDevice(t *testing.T) {
	service, store, _, deviceID := newTestService(t)
	device, ok := store.Device(deviceID)
	if !ok || device.Status != "pending" || device.DeviceName != "phone" {
		t.Fatalf("unexpected device: %+v", device)
	}
	_, err := service.Enroll(context.Background(), EnrollmentInput{InviteToken: "used", PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize)})
	if err == nil {
		t.Fatal("expected invalid invite")
	}
}

func TestChallengeRequiresApproval(t *testing.T) {
	service, store, _, deviceID := newTestService(t)
	if _, err := service.Challenge(context.Background(), deviceID); err == nil {
		t.Fatal("expected pending device rejection")
	}
	if err := store.Approve(deviceID); err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Challenge(context.Background(), deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(challenge.Nonce) != 32 || !challenge.ExpiresAt.After(time.Now()) {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}
	again, err := service.Challenge(context.Background(), deviceID)
	if err != nil || string(again.Nonce) != string(challenge.Nonce) {
		t.Fatalf("expected stable active nonce: %+v %v", again, err)
	}
}
