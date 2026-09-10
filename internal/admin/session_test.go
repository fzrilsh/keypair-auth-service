package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSessionValuesAreOpaqueAndExpire(t *testing.T) {
	store := NewSessionStore([]byte(strings.Repeat("s", 32)))
	session, err := store.Create(uuid.New(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if session.ID == "" || session.CSRFToken == "" || session.ID == session.CSRFToken {
		t.Fatal("expected opaque session values")
	}
	got, err := store.Validate(session.ID, time.Now())
	if err != nil || got.AdminID != session.AdminID {
		t.Fatalf("validate: %+v %v", got, err)
	}
	if _, err := store.Validate(session.ID, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expected expired session")
	}
	if store.ValidateCSRF(session, session.CSRFToken) != true {
		t.Fatal("expected valid csrf")
	}
	if store.ValidateCSRF(session, "wrong") {
		t.Fatal("expected invalid csrf")
	}
}
