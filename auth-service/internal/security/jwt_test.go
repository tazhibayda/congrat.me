package security_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tazhibayda/auth-service/internal/security"
)

func writeTempRSA(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp("", "rsa_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestRS256_JWKSRoundTrip(t *testing.T) {
	activePath := writeTempRSA(t)
	km, err := security.NewKeyManager("kidA", activePath, "", "")
	if err != nil {
		t.Fatal(err)
	}

	tok, err := security.MakeAccessRS256(km, "u1", "u@example.com", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	keyfunc := func(tk *jwt.Token) (interface{}, error) {
		kid, _ := tk.Header["kid"].(string)
		if pk, ok := km.PublicByKid(kid); ok {
			return pk, nil
		}
		return nil, errors.New("no key by kid")
	}
	parsed, err := jwt.ParseWithClaims(tok, &security.Claims{}, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("invalid token: %v", err)
	}
	c := parsed.Claims.(*security.Claims)
	if c.UID != "u1" || c.Email != "u@example.com" {
		t.Fatalf("claims mismatch: %#v", c)
	}
}
