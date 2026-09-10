package admin

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLoginCreatesSessionForValidPassword(t *testing.T) {
	store := NewAccountStore()
	passwordHash, err := HashPassword([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	adminID := uuid.New()
	store.Add(AdminAccount{ID: adminID, Email: "admin@example.com", PasswordHash: passwordHash})
	service := NewService(store, NewSessionStore([]byte("01234567890123456789012345678901")), time.Hour)
	session, err := service.Login(context.Background(), "ADMIN@example.com", []byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if session.AdminID != adminID {
		t.Fatalf("unexpected admin id: %v", session.AdminID)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	store := NewAccountStore()
	passwordHash, err := HashPassword([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	store.Add(AdminAccount{ID: uuid.New(), Email: "admin@example.com", PasswordHash: passwordHash})
	service := NewService(store, NewSessionStore([]byte("01234567890123456789012345678901")), time.Hour)
	if _, err := service.Login(context.Background(), "admin@example.com", []byte("wrong")); err == nil {
		t.Fatal("expected login failure")
	}
}
