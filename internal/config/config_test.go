package config

import (
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func baseEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL":                 "postgres://db",
		"ADMIN_SESSION_SECRET":         strings.Repeat("b", 32),
		"JWT_SIGNING_PRIVATE_KEY_FILE": "/tmp/signing.pem",
		"JWT_SIGNING_KEY_ID":           "key-2026-09",
		"ALLOWED_CLIENT_IDS":           "app-a,app-b",
	}
}

func TestLoadRejectsMissingRequiredSecrets(t *testing.T) {
	values := baseEnv()
	delete(values, "JWT_SIGNING_PRIVATE_KEY_FILE")
	_, err := Load(env(values))
	if err == nil || !strings.Contains(err.Error(), "JWT_SIGNING_PRIVATE_KEY_FILE") {
		t.Fatalf("expected missing signing key error, got %v", err)
	}
}

func TestLoadRejectsEmptyClientAllowlist(t *testing.T) {
	values := baseEnv()
	values["ALLOWED_CLIENT_IDS"] = " , "
	_, err := Load(env(values))
	if err == nil || !strings.Contains(err.Error(), "ALLOWED_CLIENT_IDS") {
		t.Fatalf("expected allowlist error, got %v", err)
	}
}

func TestLoadParsesAndTrimsClientAllowlist(t *testing.T) {
	values := baseEnv()
	values["ALLOWED_CLIENT_IDS"] = " app-a, app-b "
	cfg, err := Load(env(values))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedClientIDs) != 2 || cfg.AllowedClientIDs[0] != "app-a" || cfg.AllowedClientIDs[1] != "app-b" {
		t.Fatalf("unexpected clients: %#v", cfg.AllowedClientIDs)
	}
}

func TestLoadRequiresPreviousKeyIDWhenPreviousKeySet(t *testing.T) {
	values := baseEnv()
	values["JWT_PREVIOUS_PUBLIC_KEY_FILE"] = "/tmp/previous.pem"
	_, err := Load(env(values))
	if err == nil || !strings.Contains(err.Error(), "JWT_PREVIOUS_KEY_ID") {
		t.Fatalf("expected previous key id error, got %v", err)
	}
}

func TestLoadAppliesJWKSCacheDefaultShorterThanJWTLifetime(t *testing.T) {
	cfg, err := Load(env(baseEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWKSCacheMaxAge != 5*time.Minute || cfg.JWKSCacheMaxAge >= cfg.JWTLifetime {
		t.Fatalf("unexpected JWKS cache: %v", cfg.JWKSCacheMaxAge)
	}
}

func TestLoadParsesExistingProtocolValues(t *testing.T) {
	values := baseEnv()
	values["CHALLENGE_TTL"] = "45s"
	values["TIMESTAMP_SKEW"] = "20s"
	values["JWT_LIFETIME"] = "10m"
	values["ADMIN_SESSION_LIFETIME"] = "2h"
	values["REQUEST_BODY_LIMIT"] = "2048"
	cfg, err := Load(env(values))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ChallengeTTL != 45*time.Second || cfg.TimestampSkew != 20*time.Second || cfg.JWTLifetime != 10*time.Minute || cfg.AdminSessionLifetime != 2*time.Hour || cfg.RequestBodyLimit != 2048 {
		t.Fatalf("unexpected parsed values: %+v", cfg)
	}
}
func TestLoadRejectsMissingSigningKeyID(t *testing.T) {
	values := baseEnv()
	delete(values, "JWT_SIGNING_KEY_ID")
	_, err := Load(env(values))
	if err == nil || !strings.Contains(err.Error(), "JWT_SIGNING_KEY_ID") {
		t.Fatalf("expected signing key id error, got %v", err)
	}
}

func TestLoadRejectsDuplicateClientIDs(t *testing.T) {
	values := baseEnv()
	values["ALLOWED_CLIENT_IDS"] = "app-a, app-a"
	_, err := Load(env(values))
	if err == nil || !strings.Contains(err.Error(), "ALLOWED_CLIENT_IDS") {
		t.Fatalf("expected duplicate allowlist error, got %v", err)
	}
}

func TestLoadRejectsPreviousKeyIDWithoutFile(t *testing.T) {
	values := baseEnv()
	values["JWT_PREVIOUS_KEY_ID"] = "previous"
	_, err := Load(env(values))
	if err == nil || !strings.Contains(err.Error(), "JWT_PREVIOUS_PUBLIC_KEY_FILE") {
		t.Fatalf("expected previous key file error, got %v", err)
	}
}
