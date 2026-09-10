package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }

type testFetcher struct {
	keys  SigningKeys
	calls atomic.Int32
}

func (f *testFetcher) Fetch(context.Context) (SigningKeys, error) { f.calls.Add(1); return f.keys, nil }

func TestConsumerVerifierCachesAndValidatesAudience(t *testing.T) {
	keys := testSigningKeys(t)
	device := Device{ID: uuid.New(), UserID: uuid.New()}
	raw, err := IssueDeviceJWT(keys, "issuer", "app-a", device, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &testFetcher{keys: keys}
	verifier := &ConsumerVerifier{Issuer: "issuer", Audience: "app-a", Fetcher: fetcher, CacheMaxAge: time.Minute}
	if _, err := verifier.Verify(context.Background(), raw, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), raw, time.Now()); err != nil {
		t.Fatal(err)
	}
	if fetcher.calls.Load() != 1 {
		t.Fatalf("expected one fetch, got %d", fetcher.calls.Load())
	}
	wrongAudience := &ConsumerVerifier{Issuer: "issuer", Audience: "app-b", Fetcher: &testFetcher{keys: keys}, CacheMaxAge: time.Minute}
	if _, err := wrongAudience.Verify(context.Background(), raw, time.Now()); err == nil {
		t.Fatal("expected audience rejection")
	}
}

func TestHTTPJWKSFetcher(t *testing.T) {
	keys := testSigningKeys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mustJSON(keys.JWKS()))
	}))
	defer server.Close()
	fetcher := &HTTPJWKSFetcher{URL: server.URL, Client: server.Client()}
	got, err := fetcher.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.ActiveKID != keys.ActiveKID || len(got.ActivePublic) != 32 {
		t.Fatalf("unexpected fetched keys: %+v", got)
	}
}

func TestConsumerVerifierRefreshesOnlyForUnknownKey(t *testing.T) {
	keys := testSigningKeys(t)
	device := Device{ID: uuid.New(), UserID: uuid.New()}
	raw, err := IssueDeviceJWT(keys, "issuer", "app-a", device, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &testFetcher{keys: keys}
	verifier := &ConsumerVerifier{Issuer: "issuer", Audience: "app-a", Fetcher: fetcher, CacheMaxAge: time.Minute}
	if _, err := verifier.Verify(context.Background(), raw, time.Now()); err != nil {
		t.Fatal(err)
	}
	wrongAudience := &ConsumerVerifier{Issuer: "issuer", Audience: "app-b", Fetcher: fetcher, CacheMaxAge: time.Minute}
	if _, err := wrongAudience.Verify(context.Background(), raw, time.Now()); err == nil {
		t.Fatal("expected audience rejection")
	}
	if fetcher.calls.Load() != 2 {
		t.Fatalf("expected no refresh for known key, got %d fetches", fetcher.calls.Load())
	}
}

func TestHTTPJWKSFetcherRejectsUnsafeResponses(t *testing.T) {
	keys := testSigningKeys(t)
	cases := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{name: "wrong content type", contentType: "text/plain", body: mustJSON(keys.JWKS())},
		{name: "private field", contentType: "application/json", body: []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"x","use":"sig","alg":"EdDSA","kid":"active","d":"private"}]}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()
			if _, err := (&HTTPJWKSFetcher{URL: server.URL, Client: server.Client()}).Fetch(context.Background()); err == nil {
				t.Fatal("expected unsafe JWKS response rejection")
			}
		})
	}
}
