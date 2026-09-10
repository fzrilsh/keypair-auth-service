package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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

func TestRemoveInviteUsesOpaqueIDAndPreservesUsedInvites(t *testing.T) {
	service, store, _, _ := newTestService(t)
	created, err := service.CreateInvite(t.Context(), uuid.New(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	invites, err := service.ListInvites(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var createdID uuid.UUID
	for _, invite := range invites {
		if invite.Prefix == created.Prefix {
			createdID = invite.ID
			break
		}
	}
	if createdID == uuid.Nil {
		t.Fatal("expected an opaque invite ID")
	}
	if err := service.RemoveInvite(t.Context(), createdID); err != nil {
		t.Fatalf("remove invite: %v", err)
	}
	if err := service.RemoveInvite(t.Context(), createdID); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected repeated remove conflict, got %v", err)
	}

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	used, err := service.CreateInvite(t.Context(), uuid.New(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(t.Context(), EnrollmentInput{InviteToken: used.Token, PublicKey: public, DeviceName: "used"}); err != nil {
		t.Fatal(err)
	}
	invites, err = service.ListInvites(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var usedID uuid.UUID
	for _, invite := range invites {
		if invite.Prefix == used.Prefix {
			usedID = invite.ID
			break
		}
	}
	if usedID == uuid.Nil {
		t.Fatal("expected used invite ID")
	}
	if err := service.RemoveInvite(t.Context(), usedID); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected used invite conflict, got %v", err)
	}

	expiredToken, expiredHash, expiredPrefix, err := GenerateInviteToken()
	if err != nil {
		t.Fatal(err)
	}
	expiredID := uuid.New()
	if err := store.CreateInvite(t.Context(), expiredID, expiredHash, expiredPrefix, uuid.New(), time.Now().Add(-time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if err := service.RemoveInvite(t.Context(), expiredID); err != nil {
		t.Fatalf("expired unused invite should be removable: %v", err)
	}
	_ = expiredToken
}

func TestInviteScopesAreCopiedToEnrolledDevice(t *testing.T) {
	store := NewMemoryStore()
	service := NewService(store, ServiceConfig{})
	scope, err := service.CreateScope(t.Context(), "profile:read")
	if err != nil {
		t.Fatal(err)
	}
	invite, err := service.CreateInvite(t.Context(), uuid.New(), time.Minute, scope.ID)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Enroll(t.Context(), EnrollmentInput{InviteToken: invite.Token, PublicKey: public, DeviceName: "scoped-device"})
	if err != nil {
		t.Fatal(err)
	}
	device, ok := store.Device(result.DeviceID)
	if !ok || len(device.Scopes) != 1 || device.Scopes[0].Name != "profile:read" {
		t.Fatalf("invite scopes were not copied: %+v", device)
	}
}

func TestScopeNamesRejectWhitespaceAndControlCharacters(t *testing.T) {
	service := NewService(NewMemoryStore(), ServiceConfig{})
	for _, name := range []string{"profile:\vread", "profile:\fread", "profile:\u00a0read"} {
		if _, err := service.CreateScope(t.Context(), name); err == nil {
			t.Fatalf("expected invalid scope name %q", name)
		}
	}
}
