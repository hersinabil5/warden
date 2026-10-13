package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// maxJWKSBytes bounds a fetched key set.
const maxJWKSBytes = 1 << 20

// RemoteKeysOptions configures RemoteKeys.
type RemoteKeysOptions struct {
	// MinRefresh is the least time between fetches. An unknown kid
	// triggers a refetch only after it, so forged kids cannot hammer the
	// JWKS endpoint. Zero means 30 s.
	MinRefresh time.Duration
	Now        func() time.Time
}

// RemoteKeys is a KeyFunc source for upstreams: it fetches Warden's JWKS
// and refetches when it meets a kid it doesn't know (key rotation).
type RemoteKeys struct {
	client *http.Client
	url    string
	opts   RemoteKeysOptions

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	lastFetch time.Time
}

// NewRemoteKeys returns a key source for the JWKS at url. The client should
// have a timeout; RemoteKeys holds a lock while fetching.
func NewRemoteKeys(client *http.Client, url string, opts RemoteKeysOptions) *RemoteKeys {
	if opts.MinRefresh <= 0 {
		opts.MinRefresh = 30 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &RemoteKeys{client: client, url: url, opts: opts}
}

// Key implements KeyFunc.
func (r *RemoteKeys) Key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys[kid]; ok {
		return k, nil
	}
	now := r.opts.Now()
	if !r.lastFetch.IsZero() && now.Sub(r.lastFetch) < r.opts.MinRefresh {
		return nil, ErrUnknownKey
	}
	r.lastFetch = now
	keys, err := r.fetch(ctx)
	if err != nil {
		return nil, err
	}
	r.keys = keys
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

// fetch downloads the key set, keeping only ES256 signing keys on P-256.
func (r *RemoteKeys) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, fmt.Errorf("identity: JWKS request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: fetching JWKS: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("identity: reading JWKS: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("identity: JWKS larger than %d bytes", maxJWKSBytes)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("identity: decoding JWKS: %w", err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		pub, ok := k.Key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() || k.KeyID == "" ||
			k.Algorithm != string(jose.ES256) || (k.Use != "" && k.Use != "sig") {
			continue
		}
		keys[k.KeyID] = pub
	}
	return keys, nil
}
