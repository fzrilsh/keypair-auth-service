package admin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"keypair-auth-service/internal/db"
)

type PostgresAccountStore struct {
	queries *db.Queries
}

func NewPostgresAccountStore(pool *pgxpool.Pool) *PostgresAccountStore {
	return &PostgresAccountStore{queries: db.New(pool)}
}

func (s *PostgresAccountStore) Get(ctx context.Context, email string) (AdminAccount, bool) {
	row, err := s.queries.GetAdminByEmail(ctx, email)
	if err != nil {
		return AdminAccount{}, false
	}
	return AdminAccount{ID: uuid.UUID(row.ID.Bytes), Email: row.Email, PasswordHash: row.PasswordHash}, true
}

type PostgresSessionStore struct {
	queries *db.Queries
	secret  []byte
}

func NewPostgresSessionStore(pool *pgxpool.Pool, secret []byte) *PostgresSessionStore {
	return &PostgresSessionStore{queries: db.New(pool), secret: append([]byte(nil), secret...)}
}

func (s *PostgresSessionStore) digestBytes(value string) []byte {
	digest := s.digest(value)
	return digest[:]
}

var _ SessionBackend = (*PostgresSessionStore)(nil)
var _ AccountBackend = (*PostgresAccountStore)(nil)

func (s *PostgresSessionStore) CreateSession(ctx context.Context, adminID uuid.UUID, lifetime time.Duration) (Session, error) {
	return s.Create(ctx, adminID, lifetime)
}

func (s *PostgresSessionStore) ValidateSession(ctx context.Context, id string, now time.Time) (Session, error) {
	return s.Validate(ctx, id, now)
}

func (s *PostgresSessionStore) DeleteSession(ctx context.Context, id string) error {
	return s.Delete(ctx, id)
}

func (s *PostgresSessionStore) ValidateCSRFToken(ctx context.Context, session Session, token string) bool {
	return s.ValidateCSRF(ctx, session, token)
}

func (s *PostgresSessionStore) Create(ctx context.Context, adminID uuid.UUID, lifetime time.Duration) (Session, error) {
	var rawID, rawCSRF [32]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return Session{}, err
	}
	if _, err := rand.Read(rawCSRF[:]); err != nil {
		return Session{}, err
	}
	now := time.Now()
	session := Session{AdminID: adminID, ID: base64.RawURLEncoding.EncodeToString(rawID[:]), CSRFToken: base64.RawURLEncoding.EncodeToString(rawCSRF[:]), ExpiresAt: now.Add(lifetime)}
	if err := s.queries.InsertSession(ctx, db.InsertSessionParams{
		SessionIDHash: s.digestBytes(session.ID), AdminID: pgtype.UUID{Bytes: adminID, Valid: true},
		CsrfTokenHash: s.digestBytes(session.CSRFToken), ExpiresAt: pgtype.Timestamptz{Time: session.ExpiresAt, Valid: true},
	}); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (s *PostgresSessionStore) Validate(ctx context.Context, id string, now time.Time) (Session, error) {
	row, err := s.queries.GetSession(ctx, s.digestBytes(id))
	if err != nil || !row.AdminID.Valid || !row.ExpiresAt.Valid || !now.Before(row.ExpiresAt.Time) {
		return Session{}, errors.New("invalid session")
	}
	return Session{AdminID: uuid.UUID(row.AdminID.Bytes), ID: id, ExpiresAt: row.ExpiresAt.Time}, nil
}

func (s *PostgresSessionStore) Delete(ctx context.Context, id string) error {
	return s.queries.DeleteSession(ctx, s.digestBytes(id))
}

func (s *PostgresSessionStore) ValidateCSRF(ctx context.Context, session Session, token string) bool {
	row, err := s.queries.GetSession(ctx, s.digestBytes(session.ID))
	if err != nil {
		return false
	}
	return hmac.Equal(row.CsrfTokenHash, s.digestBytes(token))
}

func (s *PostgresSessionStore) digest(value string) [32]byte {
	h := hmac.New(sha256.New, s.secret)
	_, _ = h.Write([]byte(value))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

var _ SessionBackend = (*PostgresSessionStore)(nil)
var _ AccountBackend = (*PostgresAccountStore)(nil)
