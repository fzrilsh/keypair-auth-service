package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"keypair-auth-service/internal/admin"
	"keypair-auth-service/internal/auth"
	"keypair-auth-service/internal/config"
	dbstore "keypair-auth-service/internal/db"
	"keypair-auth-service/internal/httputil"
	"keypair-auth-service/internal/web"
)

type commandRunner func(context.Context, io.Reader, io.Writer) error

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, commands map[string]commandRunner) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: server <serve|migrate|bootstrap-admin>")
	}
	command, ok := commands[args[0]]
	if !ok {
		return fmt.Errorf("unknown command %q", args[0])
	}
	return command(context.Background(), stdin, stdout)
}

func main() {
	commands := map[string]commandRunner{
		"serve":   func(ctx context.Context, _ io.Reader, _ io.Writer) error { return serve(ctx) },
		"migrate": func(ctx context.Context, _ io.Reader, _ io.Writer) error { return migrate(ctx) },
		"bootstrap-admin": func(ctx context.Context, stdin io.Reader, _ io.Writer) error {
			return bootstrapAdmin(ctx, stdin, os.Args[2:])
		},
	}
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, commands); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(parent context.Context) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	keys, err := auth.LoadSigningKeys(cfg.JWTSigningPrivateKeyFile, cfg.JWTSigningKeyID, cfg.JWTPreviousPublicKeyFile, cfg.JWTPreviousKeyID)
	if err != nil {
		return fmt.Errorf("signing keys: %w", err)
	}
	allowedAudiences := make(map[string]struct{}, len(cfg.AllowedClientIDs))
	for _, clientID := range cfg.AllowedClientIDs {
		allowedAudiences[clientID] = struct{}{}
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := dbstore.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	store := auth.NewPostgresStore(pool)
	authService := auth.NewService(store, auth.ServiceConfig{
		Keys: keys, AllowedAudiences: allowedAudiences, Issuer: cfg.JWTIssuer, NonceTTL: cfg.ChallengeTTL,
		TimestampSkew: cfg.TimestampSkew, JWTLifetime: cfg.JWTLifetime,
	})
	accounts := admin.NewPostgresAccountStore(pool)
	sessions := admin.NewPostgresSessionStore(pool, cfg.AdminSessionSecret)
	adminService := admin.NewService(accounts, sessions, cfg.AdminSessionLifetime)
	api := web.APIHandlers{Auth: authService, RequestBodyLimit: cfg.RequestBodyLimit}
	adminHandlers := web.AdminHandlers{Auth: authService, Admin: adminService, Sessions: sessions, InviteTTL: cfg.InviteTTL}
	router := web.NewRouter(web.Dependencies{API: api, Admin: adminHandlers, AdminSessions: sessions, JWKS: web.JWKSHandler{Keys: keys, CacheMaxAge: cfg.JWKSCacheMaxAge}, Ready: pool.Ping})

	stopCleanup := startCleanup(ctx, pool, cfg.CleanupInterval)
	defer stopCleanup()
	server := &http.Server{
		Addr: cfg.HTTPAddr, Handler: httputil.SecurityHeaders(router),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Default().Info("server started", "addr", cfg.HTTPAddr)
	if err := server.ListenAndServe(); errors.Is(err, http.ErrServerClosed) {
		return nil
	} else {
		return err
	}
}

func startCleanup(ctx context.Context, pool *pgxpool.Pool, interval time.Duration) func() {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				counts, err := dbstore.CleanupExpired(cleanupCtx, dbstore.New(pool), now)
				cancel()
				if err != nil {
					slog.Default().Error("database cleanup failed", "error", err)
					continue
				}
				slog.Default().Debug("database cleanup completed", "nonces", counts.Nonces, "sessions", counts.Sessions, "invites", counts.Invites)
			}
		}
	}()
	return func() { <-done }
}

func migrate(ctx context.Context) error {
	cfg, err := config.LoadDatabase(os.Getenv)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	goose.SetBaseFS(dbstore.Migrations)
	defer goose.SetBaseFS(nil)
	return goose.UpContext(ctx, db, "migrations")
}

func bootstrapAdmin(ctx context.Context, stdin io.Reader, args []string) error {
	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	email := flags.String("email", "", "admin email")
	passwordStdin := flags.Bool("password-stdin", false, "read password from stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*passwordStdin || strings.TrimSpace(*email) == "" {
		return fmt.Errorf("bootstrap-admin requires --email and --password-stdin")
	}
	cfg, err := config.LoadDatabase(os.Getenv)
	if err != nil {
		return err
	}
	password, err := io.ReadAll(io.LimitReader(stdin, 1025))
	if err != nil {
		return err
	}
	password = []byte(strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r"))
	hash, err := admin.HashPassword(password)
	if err != nil {
		return err
	}
	pool, err := dbstore.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	queries := dbstore.New(pool)
	normalized, err := admin.NormalizeEmail(*email)
	if err != nil {
		return err
	}
	_, err = queries.InsertAdmin(ctx, dbstore.InsertAdminParams{Email: normalized, PasswordHash: hash})
	return err
}
