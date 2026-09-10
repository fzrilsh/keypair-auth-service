package auth

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/google/uuid"
)

type VerifyInput struct {
	DeviceID  uuid.UUID
	ClientID  string
	Signature []byte
	Timestamp int64
}

type TokenResult struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
}

func (s *Service) Verify(ctx context.Context, input VerifyInput) (TokenResult, error) {
	if err := ctx.Err(); err != nil {
		return TokenResult{}, err
	}
	if input.ClientID == "" {
		return TokenResult{}, ErrInvalidCredential
	}
	if _, ok := s.cfg.AllowedAudiences[input.ClientID]; !ok {
		return TokenResult{}, ErrInvalidCredential
	}
	if len(input.Signature) != ed25519.SignatureSize {
		return TokenResult{}, ErrInvalidCredential
	}
	now := time.Now()
	device, err := s.store.VerifyDevice(ctx, input, now, s.cfg.TimestampSkew, func(device Device, nonce []byte) bool {
		if absDuration(now.Sub(time.Unix(input.Timestamp, 0))) > s.cfg.TimestampSkew {
			return false
		}
		return ed25519.Verify(device.PublicKey, CanonicalMessage(input.DeviceID, nonce, input.Timestamp), input.Signature)
	})
	if err != nil {
		return TokenResult{}, err
	}
	token, err := IssueDeviceJWT(s.cfg.Keys, s.cfg.Issuer, input.ClientID, device, s.cfg.JWTLifetime, now)
	if err != nil {
		return TokenResult{}, err
	}
	return TokenResult{AccessToken: token, TokenType: "Bearer", ExpiresIn: int64(s.cfg.JWTLifetime / time.Second)}, nil
}
