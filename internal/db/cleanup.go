package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type CleanupCounts struct{ Nonces, Sessions, Invites int64 }

func CleanupExpired(ctx context.Context, queries *Queries, now time.Time) (CleanupCounts, error) {
	stamp := pgtype.Timestamptz{Time: now, Valid: true}
	nonces, err := queries.CleanupNonces(ctx, stamp)
	if err != nil {
		return CleanupCounts{}, err
	}
	sessions, err := queries.CleanupSessions(ctx, stamp)
	if err != nil {
		return CleanupCounts{}, err
	}
	invites, err := queries.CleanupInvites(ctx, CleanupInvitesParams{ExpiresAt: stamp, UsedAt: stamp})
	if err != nil {
		return CleanupCounts{}, err
	}
	return CleanupCounts{Nonces: nonces, Sessions: sessions, Invites: invites}, nil
}
