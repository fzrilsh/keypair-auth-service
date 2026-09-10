package admin

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func NormalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > 320 || !strings.Contains(email, "@") {
		return "", fmt.Errorf("invalid email")
	}
	return email, nil
}

func HashPassword(password []byte) (string, error) {
	if len(password) == 0 || len(password) > 1024 {
		return "", fmt.Errorf("invalid password")
	}
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	return string(hash), err
}

func VerifyPassword(hash string, password []byte) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), password) == nil
}
