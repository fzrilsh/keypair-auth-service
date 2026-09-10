package web

import (
	"net/http"
	"strconv"
	"time"

	"keypair-auth-service/internal/auth"
)

type JWKSHandler struct {
	Keys        auth.SigningKeys
	CacheMaxAge time.Duration
}

func (h JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := h.Keys.JWKSJSON()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	maxAge := int(h.CacheMaxAge.Seconds())
	if maxAge <= 0 {
		maxAge = 300
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(maxAge))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
