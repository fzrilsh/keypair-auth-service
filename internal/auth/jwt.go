package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	DeviceID string `json:"device_id"`
	UserID   string `json:"user_id"`
	Scope    string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// IssueDeviceJWT issues a token without a scope for callers that do not need one.
func IssueDeviceJWT(keys SigningKeys, issuer, clientID string, device Device, lifetime time.Duration, now time.Time) (string, error) {
	return IssueDeviceJWTWithScope(keys, issuer, clientID, device, "", lifetime, now)
}

func IssueDeviceJWTWithScope(keys SigningKeys, issuer, clientID string, device Device, scope string, lifetime time.Duration, now time.Time) (string, error) {
	if len(keys.ActivePrivate) != ed25519.PrivateKeySize || len(keys.ActivePublic) != ed25519.PublicKeySize || !ed25519.PublicKey(keys.ActivePrivate.Public().(ed25519.PublicKey)).Equal(keys.ActivePublic) || !validKID(keys.ActiveKID) || issuer == "" || clientID == "" || lifetime <= 0 {
		return "", fmt.Errorf("invalid JWT signing configuration")
	}
	var jtiBytes [16]byte
	if _, err := rand.Read(jtiBytes[:]); err != nil {
		return "", err
	}
	claims := Claims{
		DeviceID: device.ID.String(), UserID: device.UserID.String(), Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer, Subject: device.ID.String(), ID: hex.EncodeToString(jtiBytes[:]),
			Audience: jwt.ClaimStrings{clientID}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = keys.ActiveKID
	return token.SignedString(keys.ActivePrivate)
}

func ParseAndValidateJWT(keys SigningKeys, issuer, audience, raw string, now time.Time) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected signing method")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("missing key id")
		}
		key, ok := keys.PublicKey(kid)
		if !ok {
			return nil, fmt.Errorf("unknown key id")
		}
		return key, nil
	}, jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// ParseJWT is retained as a compatibility wrapper for callers migrating to EdDSA.
func ParseJWT(keys SigningKeys, issuer, audience, raw string) (*Claims, error) {
	return ParseAndValidateJWT(keys, issuer, audience, raw, time.Now())
}

func parseUUID(value string) (uuid.UUID, error) { return uuid.Parse(value) }
