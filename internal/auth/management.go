package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
)

type InviteResult struct {
	Token     string
	Prefix    string
	UserID    uuid.UUID
	ExpiresAt time.Time
}

func (s *Service) CreateInvite(ctx context.Context, userID uuid.UUID, lifetime time.Duration) (InviteResult, error) {
	if err := ctx.Err(); err != nil {
		return InviteResult{}, err
	}
	if lifetime <= 0 {
		return InviteResult{}, ErrInvalidCredential
	}
	plain, hash, prefix, err := GenerateInviteToken()
	if err != nil {
		return InviteResult{}, err
	}
	expiresAt := time.Now().Add(lifetime)
	if err := s.store.CreateInvite(ctx, uuid.New(), hash, prefix, userID, expiresAt); err != nil {
		return InviteResult{}, err
	}
	return InviteResult{Token: plain, Prefix: prefix, UserID: userID, ExpiresAt: expiresAt}, nil
}

func (s *Service) ListDevices(ctx context.Context) ([]Device, error) {
	return s.store.ListDevices(ctx)
}

func (s *Service) ListInvites(ctx context.Context) ([]Invite, error) {
	return s.store.ListInvites(ctx)
}

func (s *Service) RemoveInvite(ctx context.Context, id uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id == uuid.Nil {
		return ErrConflict
	}
	return s.store.RemoveInvite(ctx, id)
}

func (s *Service) Approve(ctx context.Context, id uuid.UUID) error {
	return s.store.ApproveDevice(ctx, id)
}

func (s *Service) Revoke(ctx context.Context, id uuid.UUID) error {
	return s.store.RevokeDevice(ctx, id)
}

func inviteHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func randomInvitePrefix(token string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(token))
	if len(encoded) > 12 {
		return encoded[:12]
	}
	return encoded
}

func randomBytes(length int) ([]byte, error) {
	value := make([]byte, length)
	_, err := rand.Read(value)
	return value, err
}
