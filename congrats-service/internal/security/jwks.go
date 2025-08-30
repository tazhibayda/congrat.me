package security

import (
	"context"
	"crypto/rsa"
	_ "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Fetcher struct {
	JWKSURL string
	TTL     time.Duration

	mu    sync.RWMutex
	keys  map[string]*rsa.PublicKey
	expAt time.Time

	http *http.Client
}

func NewFetcher(jwksURL string, ttl time.Duration) *Fetcher {
	return &Fetcher{
		JWKSURL: jwksURL,
		TTL:     ttl,
		keys:    make(map[string]*rsa.PublicKey),
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"` // base64url
	E   string `json:"e"` // base64url
}
type jwks struct {
	Keys []jwk `json:"keys"`
}

func (f *Fetcher) refresh(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.JWKSURL, nil)
	resp, err := f.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	tmp := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(eb) == 0 {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 + int(b)
		}
		tmp[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: e,
		}
	}
	f.mu.Lock()
	f.keys = tmp
	f.expAt = time.Now().Add(f.TTL)
	f.mu.Unlock()
	return nil
}

func (f *Fetcher) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	f.mu.RLock()
	if pk, ok := f.keys[kid]; ok && time.Now().Before(f.expAt) {
		f.mu.RUnlock()
		return pk, nil
	}
	f.mu.RUnlock()

	// обновим кэш
	if err := f.refresh(ctx); err != nil {
		return nil, err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if pk, ok := f.keys[kid]; ok {
		return pk, nil
	}
	return nil, errors.New("kid not found in JWKS")
}

type Claims struct {
	UID   string `json:"uid"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func (f *Fetcher) ParseAndVerify(ctx context.Context, tokenStr string) (*Claims, error) {
	var kid string
	// быстрый парс заголовка, чтобы достать kid
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	token, parts, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil || len(parts) != 3 {
		return nil, errors.New("bad token")
	}
	if hdr, ok := token.Header["kid"].(string); ok {
		kid = hdr
	}
	if kid == "" {
		return nil, errors.New("no kid")
	}
	pub, err := f.getKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	claims := &Claims{}
	// полноценная верификация подписи
	_, err = jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("bad method")
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, err
	}
	return claims, nil
}
