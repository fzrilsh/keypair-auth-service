package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL              string
	JWTSigningPrivateKeyFile string
	JWTSigningKeyID          string
	JWTPreviousPublicKeyFile string
	JWTPreviousKeyID         string
	AllowedClientIDs         []string
	JWKSCacheMaxAge          time.Duration
	AdminSessionSecret       []byte
	HTTPAddr                 string
	JWTIssuer                string
	InviteTTL                time.Duration
	ChallengeTTL             time.Duration
	TimestampSkew            time.Duration
	JWTLifetime              time.Duration
	AdminSessionLifetime     time.Duration
	CleanupInterval          time.Duration
	RequestBodyLimit         int64
}

func LoadDatabase(getenv func(string) string) (Config, error) {
	databaseURL := strings.TrimSpace(getenv("DATABASE_URL"))
	if databaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	return Config{DatabaseURL: databaseURL}, nil
}

func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		DatabaseURL:              strings.TrimSpace(getenv("DATABASE_URL")),
		JWTSigningPrivateKeyFile: strings.TrimSpace(getenv("JWT_SIGNING_PRIVATE_KEY_FILE")),
		JWTSigningKeyID:          strings.TrimSpace(getenv("JWT_SIGNING_KEY_ID")),
		JWTPreviousPublicKeyFile: strings.TrimSpace(getenv("JWT_PREVIOUS_PUBLIC_KEY_FILE")),
		JWTPreviousKeyID:         strings.TrimSpace(getenv("JWT_PREVIOUS_KEY_ID")),
		HTTPAddr:                 valueOr(getenv("HTTP_ADDR"), ":8080"),
		JWTIssuer:                valueOr(getenv("JWT_ISSUER"), "keypair-auth-service"),
		InviteTTL:                15 * time.Minute, ChallengeTTL: 60 * time.Second,
		TimestampSkew: 30 * time.Second, JWTLifetime: 15 * time.Minute,
		AdminSessionLifetime: 8 * time.Hour, CleanupInterval: 5 * time.Minute,
		JWKSCacheMaxAge: 5 * time.Minute, RequestBodyLimit: 1 << 20,
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWTSigningPrivateKeyFile == "" {
		return Config{}, fmt.Errorf("JWT_SIGNING_PRIVATE_KEY_FILE is required")
	}
	if !validKeyID(cfg.JWTSigningKeyID) {
		return Config{}, fmt.Errorf("JWT_SIGNING_KEY_ID is required and must contain only letters, digits, '.', '_' or '-'")
	}
	if cfg.JWTPreviousPublicKeyFile != "" && !validKeyID(cfg.JWTPreviousKeyID) {
		return Config{}, fmt.Errorf("JWT_PREVIOUS_KEY_ID is required when JWT_PREVIOUS_PUBLIC_KEY_FILE is set")
	}
	if cfg.JWTPreviousPublicKeyFile == "" && cfg.JWTPreviousKeyID != "" {
		return Config{}, fmt.Errorf("JWT_PREVIOUS_PUBLIC_KEY_FILE is required when JWT_PREVIOUS_KEY_ID is set")
	}
	var err error
	cfg.AllowedClientIDs, err = parseClientIDs(getenv("ALLOWED_CLIENT_IDS"))
	if err != nil {
		return Config{}, err
	}
	adminSecret := []byte(getenv("ADMIN_SESSION_SECRET"))
	if len(adminSecret) < 32 {
		return Config{}, fmt.Errorf("ADMIN_SESSION_SECRET must contain at least 32 bytes")
	}
	cfg.AdminSessionSecret = adminSecret
	if cfg.InviteTTL, err = duration(getenv, "INVITE_TTL", cfg.InviteTTL); err != nil {
		return Config{}, err
	}
	if cfg.ChallengeTTL, err = duration(getenv, "CHALLENGE_TTL", cfg.ChallengeTTL); err != nil {
		return Config{}, err
	}
	if cfg.TimestampSkew, err = duration(getenv, "TIMESTAMP_SKEW", cfg.TimestampSkew); err != nil {
		return Config{}, err
	}
	if cfg.JWTLifetime, err = duration(getenv, "JWT_LIFETIME", cfg.JWTLifetime); err != nil {
		return Config{}, err
	}
	if cfg.AdminSessionLifetime, err = duration(getenv, "ADMIN_SESSION_LIFETIME", cfg.AdminSessionLifetime); err != nil {
		return Config{}, err
	}
	if cfg.CleanupInterval, err = duration(getenv, "CLEANUP_INTERVAL", cfg.CleanupInterval); err != nil {
		return Config{}, err
	}
	if cfg.JWKSCacheMaxAge, err = duration(getenv, "JWKS_CACHE_MAX_AGE", cfg.JWKSCacheMaxAge); err != nil {
		return Config{}, err
	}
	if cfg.JWKSCacheMaxAge >= cfg.JWTLifetime {
		return Config{}, fmt.Errorf("JWKS_CACHE_MAX_AGE must be shorter than JWT_LIFETIME")
	}
	if raw := strings.TrimSpace(getenv("REQUEST_BODY_LIMIT")); raw != "" {
		cfg.RequestBodyLimit, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || cfg.RequestBodyLimit <= 0 {
			return Config{}, fmt.Errorf("REQUEST_BODY_LIMIT must be a positive integer")
		}
	}
	for name, value := range map[string]time.Duration{"INVITE_TTL": cfg.InviteTTL, "CHALLENGE_TTL": cfg.ChallengeTTL, "TIMESTAMP_SKEW": cfg.TimestampSkew, "JWT_LIFETIME": cfg.JWTLifetime, "ADMIN_SESSION_LIFETIME": cfg.AdminSessionLifetime, "CLEANUP_INTERVAL": cfg.CleanupInterval, "JWKS_CACHE_MAX_AGE": cfg.JWKSCacheMaxAge} {
		if value <= 0 {
			return Config{}, fmt.Errorf("%s must be positive", name)
		}
	}
	return cfg, nil
}

func parseClientIDs(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	seen := map[string]struct{}{}
	result := []string{}
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, fmt.Errorf("ALLOWED_CLIENT_IDS must contain non-empty values")
		}
		if !validClientID(value) {
			return nil, fmt.Errorf("ALLOWED_CLIENT_IDS contains invalid client ID")
		}
		if _, ok := seen[value]; ok {
			return nil, fmt.Errorf("ALLOWED_CLIENT_IDS contains duplicate client ID")
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("ALLOWED_CLIENT_IDS is required")
	}
	return result, nil
}
func validKeyID(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
func validClientID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}
func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
func duration(getenv func(string) string, name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration", name)
	}
	return value, nil
}
