package admin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Session struct {
	AdminID   uuid.UUID
	ID        string
	CSRFToken string
	ExpiresAt time.Time
}

type SessionBackend interface {
	CreateSession(context.Context, uuid.UUID, time.Duration) (Session, error)
	ValidateSession(context.Context, string, time.Time) (Session, error)
	DeleteSession(context.Context, string) error
	ValidateCSRFToken(context.Context, Session, string) bool
}

type storedSession struct{ session Session }

type SessionStore struct {
	mu     sync.Mutex
	secret []byte
	items  map[[32]byte]storedSession
}

func NewSessionStore(secret []byte) *SessionStore {
	return &SessionStore{secret: append([]byte(nil), secret...), items: make(map[[32]byte]storedSession)}
}

func (s *SessionStore) Create(adminID uuid.UUID, lifetime time.Duration) (Session, error) {
	return s.CreateSession(context.Background(), adminID, lifetime)
}

func (s *SessionStore) CreateSession(ctx context.Context, adminID uuid.UUID, lifetime time.Duration) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	var rawID, rawCSRF [32]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return Session{}, err
	}
	if _, err := rand.Read(rawCSRF[:]); err != nil {
		return Session{}, err
	}
	session := Session{AdminID: adminID, ID: base64.RawURLEncoding.EncodeToString(rawID[:]), CSRFToken: base64.RawURLEncoding.EncodeToString(rawCSRF[:]), ExpiresAt: time.Now().Add(lifetime)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[s.digest(session.ID)] = storedSession{session: session}
	return session, nil
}

func (s *SessionStore) Validate(id string, now time.Time) (Session, error) {
	return s.ValidateSession(context.Background(), id, now)
}

func (s *SessionStore) ValidateSession(ctx context.Context, id string, now time.Time) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.items[s.digest(id)]
	if !ok || !now.Before(stored.session.ExpiresAt) || !hmac.Equal([]byte(id), []byte(stored.session.ID)) {
		return Session{}, errors.New("invalid session")
	}
	return stored.session, nil
}

func (s *SessionStore) Delete(id string) { _ = s.DeleteSession(context.Background(), id) }

func (s *SessionStore) DeleteSession(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, s.digest(id))
	return nil
}

func (s *SessionStore) ValidateCSRF(session Session, token string) bool {
	return s.ValidateCSRFToken(context.Background(), session, token)
}

func (s *SessionStore) ValidateCSRFToken(ctx context.Context, session Session, token string) bool {
	return ctx.Err() == nil && hmac.Equal([]byte(session.CSRFToken), []byte(token))
}

func (s *SessionStore) digest(value string) [32]byte {
	h := hmac.New(sha256.New, s.secret)
	_, _ = h.Write([]byte(value))
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
