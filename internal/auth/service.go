package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidCredential = errors.New("invalid credential")
	ErrConflict          = errors.New("state conflict")
	ErrNotFound          = errors.New("not found")
)

type Device struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	PublicKey  ed25519.PublicKey
	DeviceName string
	Status     string
	CreatedAt  time.Time
	ApprovedAt *time.Time
}

type Invite struct {
	ID        uuid.UUID
	Prefix    string
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type AuthStore interface {
	CreateInvite(context.Context, uuid.UUID, []byte, string, uuid.UUID, time.Time) error
	RemoveInvite(context.Context, uuid.UUID) error
	EnrollDevice(context.Context, []byte, ed25519.PublicKey, string) (Device, error)
	IssueChallenge(context.Context, uuid.UUID, time.Duration) (ChallengeResult, error)
	VerifyDevice(context.Context, VerifyInput, time.Time, time.Duration, func(Device, []byte) bool) (Device, error)
	ListDevices(context.Context) ([]Device, error)
	ApproveDevice(context.Context, uuid.UUID) error
	RevokeDevice(context.Context, uuid.UUID) error
	ListInvites(context.Context) ([]Invite, error)
}

type invite struct {
	id        uuid.UUID
	hash      []byte
	prefix    string
	userID    uuid.UUID
	expiresAt time.Time
	usedAt    *time.Time
	createdAt time.Time
}

type nonce struct {
	value     []byte
	expiresAt time.Time
}

type MemoryStore struct {
	mu      sync.Mutex
	invites map[string]invite
	devices map[uuid.UUID]Device
	nonces  map[uuid.UUID]nonce
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{invites: make(map[string]invite), devices: make(map[uuid.UUID]Device), nonces: make(map[uuid.UUID]nonce)}
}

func (s *MemoryStore) AddInvite(hash []byte, prefix string, userID uuid.UUID, expiresAt time.Time) {
	_ = s.CreateInvite(context.Background(), uuid.New(), hash, prefix, userID, expiresAt)
}

func (s *MemoryStore) CreateInvite(_ context.Context, id uuid.UUID, hash []byte, prefix string, userID uuid.UUID, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invites[string(hash)] = invite{id: id, hash: append([]byte(nil), hash...), prefix: prefix, userID: userID, expiresAt: expiresAt, createdAt: time.Now()}
	return nil
}

func (s *MemoryStore) RemoveInvite(ctx context.Context, id uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, invite := range s.invites {
		if invite.id != id {
			continue
		}
		if invite.usedAt != nil {
			return ErrConflict
		}
		delete(s.invites, hash)
		return nil
	}
	return ErrConflict
}

func (s *MemoryStore) Device(id uuid.UUID) (Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[id]
	return device, ok
}

func (s *MemoryStore) EnrollDevice(ctx context.Context, tokenHash []byte, publicKey ed25519.PublicKey, deviceName string) (Device, error) {
	if err := ctx.Err(); err != nil {
		return Device{}, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Device{}, ErrInvalidCredential
	}
	if len([]rune(deviceName)) > 200 {
		return Device{}, fmt.Errorf("device name too long")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invites[string(tokenHash)]
	now := time.Now()
	if !ok || inv.usedAt != nil || !now.Before(inv.expiresAt) {
		return Device{}, ErrInvalidCredential
	}
	for _, device := range s.devices {
		if string(device.PublicKey) == string(publicKey) {
			return Device{}, ErrConflict
		}
	}
	used := now
	inv.usedAt = &used
	s.invites[string(tokenHash)] = inv
	id := uuid.New()
	device := Device{ID: id, UserID: inv.userID, PublicKey: append(ed25519.PublicKey(nil), publicKey...), DeviceName: deviceName, Status: "pending", CreatedAt: now}
	s.devices[id] = device
	return device, nil
}

func (s *MemoryStore) IssueChallenge(ctx context.Context, deviceID uuid.UUID, ttl time.Duration) (ChallengeResult, error) {
	if err := ctx.Err(); err != nil {
		return ChallengeResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[deviceID]
	if !ok || device.Status != "approved" {
		return ChallengeResult{}, ErrNotFound
	}
	now := time.Now()
	if existing, ok := s.nonces[deviceID]; ok && now.Before(existing.expiresAt) {
		return ChallengeResult{DeviceID: deviceID, Nonce: append([]byte(nil), existing.value...), ExpiresAt: existing.expiresAt}, nil
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return ChallengeResult{}, err
	}
	expires := now.Add(ttl)
	s.nonces[deviceID] = nonce{value: value, expiresAt: expires}
	return ChallengeResult{DeviceID: deviceID, Nonce: append([]byte(nil), value...), ExpiresAt: expires}, nil
}

func (s *MemoryStore) VerifyDevice(ctx context.Context, input VerifyInput, now time.Time, skew time.Duration, verify func(Device, []byte) bool) (Device, error) {
	if err := ctx.Err(); err != nil {
		return Device{}, err
	}
	if len(input.Signature) != ed25519.SignatureSize {
		return Device{}, ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[input.DeviceID]
	current, nonceOK := s.nonces[input.DeviceID]
	if !ok || device.Status != "approved" || !nonceOK || !now.Before(current.expiresAt) {
		return Device{}, ErrInvalidCredential
	}
	if absDuration(now.Sub(time.Unix(input.Timestamp, 0))) > skew || !verify(device, current.value) {
		return Device{}, ErrInvalidCredential
	}
	delete(s.nonces, input.DeviceID)
	return device, nil
}

func (s *MemoryStore) ListDevices(ctx context.Context) ([]Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	devices := make([]Device, 0, len(s.devices))
	for _, device := range s.devices {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].CreatedAt.After(devices[j].CreatedAt) })
	return devices, nil
}

func (s *MemoryStore) ListInvites(ctx context.Context) ([]Invite, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	invites := make([]Invite, 0, len(s.invites))
	for _, value := range s.invites {
		invites = append(invites, Invite{ID: value.id, Prefix: value.prefix, UserID: value.userID, ExpiresAt: value.expiresAt, UsedAt: value.usedAt, CreatedAt: value.createdAt})
	}
	sort.Slice(invites, func(i, j int) bool { return invites[i].CreatedAt.After(invites[j].CreatedAt) })
	return invites, nil
}

func (s *MemoryStore) Approve(id uuid.UUID) error { return s.ApproveDevice(context.Background(), id) }
func (s *MemoryStore) Revoke(id uuid.UUID) error  { return s.RevokeDevice(context.Background(), id) }

func (s *MemoryStore) ApproveDevice(ctx context.Context, id uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[id]
	if !ok {
		return ErrNotFound
	}
	if device.Status != "pending" {
		return ErrConflict
	}
	now := time.Now()
	device.Status = "approved"
	device.ApprovedAt = &now
	s.devices[id] = device
	return nil
}

func (s *MemoryStore) RevokeDevice(ctx context.Context, id uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[id]
	if !ok {
		return ErrNotFound
	}
	if device.Status != "approved" {
		return ErrConflict
	}
	device.Status = "revoked"
	s.devices[id] = device
	return nil
}

type ServiceConfig struct {
	Keys             SigningKeys
	AllowedAudiences map[string]struct{}
	Issuer           string
	NonceTTL         time.Duration
	TimestampSkew    time.Duration
	JWTLifetime      time.Duration
}

type Service struct {
	store AuthStore
	cfg   ServiceConfig
}

func NewService(store AuthStore, cfg ServiceConfig) *Service {
	return &Service{store: store, cfg: cfg}
}

type EnrollmentInput struct {
	InviteToken string
	PublicKey   ed25519.PublicKey
	DeviceName  string
}

type EnrollmentResult struct {
	DeviceID uuid.UUID
	Status   string
}

type ChallengeResult struct {
	DeviceID  uuid.UUID
	Nonce     []byte
	ExpiresAt time.Time
}

func (s *Service) Enroll(ctx context.Context, input EnrollmentInput) (EnrollmentResult, error) {
	if err := ctx.Err(); err != nil {
		return EnrollmentResult{}, err
	}
	_, hash, _, err := hashInvite(input.InviteToken)
	if err != nil {
		return EnrollmentResult{}, ErrInvalidCredential
	}
	device, err := s.store.EnrollDevice(ctx, hash, input.PublicKey, input.DeviceName)
	if err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{DeviceID: device.ID, Status: device.Status}, nil
}

func hashInvite(token string) (string, []byte, string, error) {
	digest := sha256.Sum256([]byte(token))
	return token, digest[:], "", nil
}

func (s *Service) Challenge(ctx context.Context, deviceID uuid.UUID) (ChallengeResult, error) {
	return s.store.IssueChallenge(ctx, deviceID, s.cfg.NonceTTL)
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
