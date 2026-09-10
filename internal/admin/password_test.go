package admin

import (
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	got, err := NormalizeEmail("  Admin@Example.COM ")
	if err != nil || got != "admin@example.com" {
		t.Fatalf("got %q, err %v", got, err)
	}
	if _, err := NormalizeEmail(" "); err == nil {
		t.Fatal("expected empty email rejection")
	}
}

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, []byte("correct horse battery staple")) || VerifyPassword(hash, []byte("wrong")) {
		t.Fatal("password verification mismatch")
	}
}
