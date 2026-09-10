package httputil

import (
	"net/http"
	"sync"
	"time"
)

type RateLimiter struct { mu sync.Mutex; limit int; window time.Duration; entries map[string]bucket }
type bucket struct { count int; reset time.Time }

func NewRateLimiter(limit int, window time.Duration) *RateLimiter { return &RateLimiter{limit: limit, window: window, entries: make(map[string]bucket)} }

func (l *RateLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock(); defer l.mu.Unlock()
	entry := l.entries[key]
	if !now.Before(entry.reset) { entry = bucket{reset: now.Add(l.window)} }
	if entry.count >= l.limit { l.entries[key] = entry; return false }
	entry.count++
	l.entries[key] = entry
	return true
}

func (l *RateLimiter) Middleware(key func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(key(r), time.Now()) { w.Header().Set("Retry-After", "60"); WriteJSONError(w, http.StatusTooManyRequests, "rate_limited", "too many requests"); return }
		next.ServeHTTP(w, r)
	}) }
}
