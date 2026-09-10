package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type InviteResult struct {
	Token     string
	Prefix    string
	UserID    uuid.UUID
	ExpiresAt time.Time
}

func (s *Service) CreateInvite(ctx context.Context, userID uuid.UUID, lifetime time.Duration, scopeIDs ...uuid.UUID) (InviteResult, error) {
	if err := ctx.Err(); err != nil {
		return InviteResult{}, err
	}
	if lifetime <= 0 {
		return InviteResult{}, ErrInvalidCredential
	}
	normalized, err := normalizeScopeIDs(scopeIDs)
	if err != nil {
		return InviteResult{}, err
	}
	plain, hash, prefix, err := GenerateInviteToken()
	if err != nil {
		return InviteResult{}, err
	}
	expiresAt := time.Now().Add(lifetime)
	if err := s.store.CreateInvite(ctx, uuid.New(), hash, prefix, userID, expiresAt, normalized); err != nil {
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

func (s *Service) ListScopes(ctx context.Context) ([]Scope, error) {
	return s.store.ListScopes(ctx)
}

func (s *Service) ListActiveScopes(ctx context.Context) ([]Scope, error) {
	return s.store.ListActiveScopes(ctx)
}

func (s *Service) CreateScope(ctx context.Context, name string) (Scope, error) {
	name = strings.TrimSpace(name)
	if err := validateScopeName(name); err != nil {
		return Scope{}, err
	}
	return s.store.CreateScope(ctx, name)
}

func (s *Service) DisableScope(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return ErrNotFound
	}
	return s.store.DisableScope(ctx, id)
}

func (s *Service) EnableScope(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return ErrNotFound
	}
	return s.store.EnableScope(ctx, id)
}

func (s *Service) ReplaceDeviceScopes(ctx context.Context, deviceID uuid.UUID, scopeIDs []uuid.UUID) error {
	if deviceID == uuid.Nil {
		return ErrNotFound
	}
	normalized, err := normalizeScopeIDs(scopeIDs)
	if err != nil {
		return err
	}
	return s.store.ReplaceDeviceScopes(ctx, deviceID, normalized)
}

func normalizeScopeIDs(ids []uuid.UUID) ([]uuid.UUID, error) {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	result := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if id == uuid.Nil {
			return nil, ErrConflict
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result, nil
}

func validateScopeName(name string) error {
	if name == "" || len([]rune(name)) > 128 || strings.IndexFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("scope name must be non-empty, at most 128 characters, and contain no whitespace or control characters")
	}
	return nil
}
