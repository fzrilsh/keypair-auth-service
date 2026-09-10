package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"keypair-auth-service/internal/auth"
	dbstore "keypair-auth-service/internal/db"
)

func TestPostgresMultiAppFlowAndChallengeConcurrency(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	resetDatabase(t, pool)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKeys := auth.SigningKeys{ActivePrivate: signingPrivate, ActivePublic: signingPublic, ActiveKID: "integration"}
	service := auth.NewService(auth.NewPostgresStore(pool), auth.ServiceConfig{
		Keys: signingKeys, AllowedAudiences: map[string]struct{}{"app-a": {}, "app-b": {}}, Issuer: "integration",
		NonceTTL: time.Minute, TimestampSkew: time.Minute, JWTLifetime: 15 * time.Minute,
	})
	scopeA, err := service.CreateScope(t.Context(), "profile:read")
	if err != nil {
		t.Fatal(err)
	}
	scopeB, err := service.CreateScope(t.Context(), "devices:read")
	if err != nil {
		t.Fatal(err)
	}
	invite, err := service.CreateInvite(t.Context(), uuid.New(), time.Minute, scopeA.ID)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := service.Enroll(t.Context(), auth.EnrollmentInput{InviteToken: invite.Token, PublicKey: public, DeviceName: "integration"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Approve(t.Context(), enrolled.DeviceID); err != nil {
		t.Fatal(err)
	}
	devices, err := service.ListDevices(t.Context())
	if err != nil || len(devices) != 1 || len(devices[0].Scopes) != 1 || devices[0].Scopes[0].Name != "profile:read" {
		t.Fatalf("invite scope was not copied to device: %v %+v", err, devices)
	}
	if err := service.ReplaceDeviceScopes(t.Context(), enrolled.DeviceID, []uuid.UUID{scopeA.ID, scopeB.ID}); err != nil {
		t.Fatal(err)
	}
	if err := service.DisableScope(t.Context(), scopeB.ID); err != nil {
		t.Fatal(err)
	}

	const workers = 8
	results := make(chan auth.ChallengeResult, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := service.Challenge(context.Background(), enrolled.DeviceID)
			if err != nil {
				errors <- err
				return
			}
			results <- result
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var nonce []byte
	for result := range results {
		if nonce == nil {
			nonce = result.Nonce
		} else if string(nonce) != string(result.Nonce) {
			t.Fatal("concurrent challenge requests returned different active nonces")
		}
	}

	timestamp := time.Now().Unix()
	signature := ed25519.Sign(private, auth.CanonicalMessage(enrolled.DeviceID, nonce, timestamp))
	result, err := service.Verify(t.Context(), auth.VerifyInput{DeviceID: enrolled.DeviceID, ClientID: "app-a", Signature: signature, Timestamp: timestamp})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ParseAndValidateJWT(signingKeys, "integration", "app-a", result.AccessToken, time.Now())
	if err != nil || len(claims.Audience) != 1 || claims.Audience[0] != "app-a" || claims.Scope != "profile:read" {
		t.Fatalf("unexpected app-a token: %v %+v", err, claims)
	}

	challenge, err := service.Challenge(t.Context(), enrolled.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	timestamp = time.Now().Unix()
	signature = ed25519.Sign(private, auth.CanonicalMessage(enrolled.DeviceID, challenge.Nonce, timestamp))
	result, err = service.Verify(t.Context(), auth.VerifyInput{DeviceID: enrolled.DeviceID, ClientID: "app-b", Signature: signature, Timestamp: timestamp})
	if err != nil {
		t.Fatal(err)
	}
	claims, err = auth.ParseAndValidateJWT(signingKeys, "integration", "app-b", result.AccessToken, time.Now())
	if err != nil || len(claims.Audience) != 1 || claims.Audience[0] != "app-b" {
		t.Fatalf("unexpected app-b token: %v %+v", err, claims)
	}
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("KEYPAIR_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set KEYPAIR_TEST_DATABASE_URL to a disposable PostgreSQL database")
	}
	pool, err := dbstore.Open(t.Context(), url)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	database, err := sql.Open("pgx", url)
	if err != nil {
		pool.Close()
		t.Skipf("PostgreSQL migration connection unavailable: %v", err)
	}
	defer database.Close()
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	goose.SetBaseFS(dbstore.Migrations)
	defer goose.SetBaseFS(nil)
	if err := goose.UpContext(t.Context(), database, "migrations"); err != nil {
		pool.Close()
		t.Skipf("PostgreSQL migrations unavailable: %v", err)
	}
	return pool
}

func resetDatabase(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), "TRUNCATE admin_sessions, admins, auth_nonces, invite_tokens, devices, scopes CASCADE"); err != nil {
		t.Fatal(err)
	}
}
