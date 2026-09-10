package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"keypair-auth-service/internal/db"
)

type PostgresStore struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool, queries: db.New(pool)}
}

func (s *PostgresStore) CreateInvite(ctx context.Context, id uuid.UUID, hash []byte, prefix string, userID uuid.UUID, expiresAt time.Time) error {
	return s.queries.InsertInvite(ctx, db.InsertInviteParams{
		InviteID: toPGUUID(id), TokenHash: hash, TokenPrefix: prefix, UserID: toPGUUID(userID),
		ExpiresAt: toPGTime(expiresAt),
	})
}

func (s *PostgresStore) RemoveInvite(ctx context.Context, id uuid.UUID) error {
	rows, err := s.queries.RemoveInvite(ctx, toPGUUID(id))
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrConflict
	}
	return nil
}

func (s *PostgresStore) EnrollDevice(ctx context.Context, tokenHash []byte, publicKey ed25519.PublicKey, deviceName string) (Device, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Device{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := s.queries.WithTx(tx)
	userID, err := queries.RedeemInvite(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Device{}, ErrInvalidCredential
		}
		return Device{}, err
	}
	created, err := queries.InsertDevice(ctx, db.InsertDeviceParams{
		UserID: userID, PublicKey: append([]byte(nil), publicKey...),
		DeviceName: pgtype.Text{String: deviceName, Valid: deviceName != ""},
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Device{}, ErrConflict
		}
		return Device{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Device{}, err
	}
	return fromDBDevice(created), nil
}

func (s *PostgresStore) IssueChallenge(ctx context.Context, deviceID uuid.UUID, ttl time.Duration) (ChallengeResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ChallengeResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := s.queries.WithTx(tx)
	id := toPGUUID(deviceID)
	if _, err := queries.GetApprovedDeviceForUpdate(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ChallengeResult{}, ErrNotFound
		}
		return ChallengeResult{}, err
	}
	now := time.Now()
	stored, err := queries.GetNonceForUpdate(ctx, id)
	if err == nil && stored.ExpiresAt.Valid && now.Before(stored.ExpiresAt.Time) {
		if err := tx.Commit(ctx); err != nil {
			return ChallengeResult{}, err
		}
		return ChallengeResult{DeviceID: deviceID, Nonce: append([]byte(nil), stored.Nonce...), ExpiresAt: stored.ExpiresAt.Time}, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ChallengeResult{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return ChallengeResult{}, err
	}
	expiresAt := now.Add(ttl)
	if err := queries.UpsertNonce(ctx, db.UpsertNonceParams{DeviceID: id, Nonce: nonce, ExpiresAt: toPGTime(expiresAt)}); err != nil {
		return ChallengeResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ChallengeResult{}, err
	}
	return ChallengeResult{DeviceID: deviceID, Nonce: nonce, ExpiresAt: expiresAt}, nil
}

func (s *PostgresStore) VerifyDevice(ctx context.Context, input VerifyInput, now time.Time, skew time.Duration, verify func(Device, []byte) bool) (Device, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Device{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := s.queries.WithTx(tx)
	deviceRow, err := queries.GetApprovedDevice(ctx, toPGUUID(input.DeviceID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Device{}, ErrInvalidCredential
		}
		return Device{}, err
	}
	stored, err := queries.GetNonceForUpdate(ctx, toPGUUID(input.DeviceID))
	if err != nil || !stored.ExpiresAt.Valid || !now.Before(stored.ExpiresAt.Time) {
		return Device{}, ErrInvalidCredential
	}
	device := fromDBDevice(deviceRow)
	if absDuration(now.Sub(time.Unix(input.Timestamp, 0))) > skew || !verify(device, stored.Nonce) {
		return Device{}, ErrInvalidCredential
	}
	if err := queries.DeleteNonce(ctx, toPGUUID(input.DeviceID)); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Device{}, err
	}
	return device, nil
}

func (s *PostgresStore) ListInvites(ctx context.Context) ([]Invite, error) {
	rows, err := s.queries.ListInvites(ctx)
	if err != nil {
		return nil, err
	}
	invites := make([]Invite, 0, len(rows))
	for _, row := range rows {
		invite := Invite{Prefix: row.TokenPrefix}
		if row.InviteID.Valid {
			invite.ID = uuid.UUID(row.InviteID.Bytes)
		}
		if row.UserID.Valid {
			invite.UserID = uuid.UUID(row.UserID.Bytes)
		}
		if row.ExpiresAt.Valid {
			invite.ExpiresAt = row.ExpiresAt.Time
		}
		if row.CreatedAt.Valid {
			invite.CreatedAt = row.CreatedAt.Time
		}
		if row.UsedAt.Valid {
			usedAt := row.UsedAt.Time
			invite.UsedAt = &usedAt
		}
		invites = append(invites, invite)
	}
	return invites, nil
}

func (s *PostgresStore) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.queries.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	devices := make([]Device, 0, len(rows))
	for _, row := range rows {
		devices = append(devices, fromDBDevice(row))
	}
	return devices, nil
}

func (s *PostgresStore) ApproveDevice(ctx context.Context, id uuid.UUID) error {
	_, err := s.queries.ApproveDevice(ctx, toPGUUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	return err
}

func (s *PostgresStore) RevokeDevice(ctx context.Context, id uuid.UUID) error {
	_, err := s.queries.RevokeDevice(ctx, toPGUUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	return err
}

func toPGUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
func toPGTime(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func fromDBDevice(row db.Device) Device {
	device := Device{PublicKey: append(ed25519.PublicKey(nil), row.PublicKey...), Status: row.Status}
	if row.ID.Valid {
		device.ID = uuid.UUID(row.ID.Bytes)
	}
	if row.UserID.Valid {
		device.UserID = uuid.UUID(row.UserID.Bytes)
	}
	if row.DeviceName.Valid {
		device.DeviceName = row.DeviceName.String
	}
	if row.CreatedAt.Valid {
		device.CreatedAt = row.CreatedAt.Time
	}
	if row.ApprovedAt.Valid {
		approvedAt := row.ApprovedAt.Time
		device.ApprovedAt = &approvedAt
	}
	return device
}
