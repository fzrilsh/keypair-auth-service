package admin

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

type AdminAccount struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
}

type AccountBackend interface {
	Get(context.Context, string) (AdminAccount, bool)
}

type AccountStore struct {
	mu     sync.RWMutex
	admins map[string]AdminAccount
}

func NewAccountStore() *AccountStore { return &AccountStore{admins: make(map[string]AdminAccount)} }

func (s *AccountStore) Add(account AdminAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admins[account.Email] = account
}

func (s *AccountStore) Get(_ context.Context, email string) (AdminAccount, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	account, ok := s.admins[email]
	return account, ok
}

func (s *AccountStore) GetLegacy(email string) (AdminAccount, bool) {
	return s.Get(context.Background(), email)
}

type Service struct {
	accounts    AccountBackend
	sessions    SessionBackend
	sessionLife time.Duration
}

func NewService(accounts AccountBackend, sessions SessionBackend, sessionLife time.Duration) *Service {
	return &Service{accounts: accounts, sessions: sessions, sessionLife: sessionLife}
}

func (s *Service) Login(ctx context.Context, rawEmail string, password []byte) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	email, err := NormalizeEmail(rawEmail)
	if err != nil {
		return Session{}, errors.New("invalid credentials")
	}
	account, ok := s.accounts.Get(ctx, email)
	if !ok || !VerifyPassword(account.PasswordHash, password) {
		return Session{}, errors.New("invalid credentials")
	}
	return s.sessions.CreateSession(ctx, account.ID, s.sessionLife)
}

func (s *Service) Logout(sessionID string) {
	_ = s.sessions.DeleteSession(context.Background(), sessionID)
}
