package security

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
)

type RSAKey struct {
	Kid     string
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

type KeyManager struct {
	Active *RSAKey
	Next   *RSAKey
	byKid  map[string]*rsa.PublicKey
}

func LoadPrivateKeyPEM(path string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not RSA key")
		}
		return rk, nil
	default:
		return nil, errors.New("unsupported key type: " + block.Type)
	}
}

func NewKeyManager(activeKid, activePath, nextKid, nextPath string) (*KeyManager, error) {
	actPriv, err := LoadPrivateKeyPEM(activePath)
	if err != nil {
		return nil, err
	}
	km := &KeyManager{
		Active: &RSAKey{Kid: activeKid, Private: actPriv, Public: &actPriv.PublicKey},
		byKid:  map[string]*rsa.PublicKey{activeKid: &actPriv.PublicKey},
	}
	if nextKid != "" && nextPath != "" {
		nxtPriv, err := LoadPrivateKeyPEM(nextPath)
		if err != nil {
			return nil, err
		}
		km.Next = &RSAKey{Kid: nextKid, Private: nxtPriv, Public: &nxtPriv.PublicKey}
		km.byKid[nextKid] = &nxtPriv.PublicKey
	}
	return km, nil
}

// JWKS (RFC 7517) — минимальный набор полей для RSA
type jwk struct {
	Kty string `json:"kty"` // "RSA"
	Kid string `json:"kid"`
	Use string `json:"use"` // "sig"
	Alg string `json:"alg"` // "RS256"
	N   string `json:"n"`   // base64url(modulus)
	E   string `json:"e"`   // base64url(exponent)
}
type jwks struct {
	Keys []jwk `json:"keys"`
}

func (km *KeyManager) JWKS() jwks {
	out := []jwk{}
	add := func(k *RSAKey) {
		if k == nil {
			return
		}
		n := base64.RawURLEncoding.EncodeToString(k.Public.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.Public.E)).Bytes())
		out = append(out, jwk{
			Kty: "RSA", Kid: k.Kid, Use: "sig", Alg: "RS256", N: n, E: e,
		})
	}
	add(km.Active)
	add(km.Next)
	return jwks{Keys: out}
}

func (km *KeyManager) PublicByKid(kid string) (*rsa.PublicKey, bool) {
	pk, ok := km.byKid[kid]
	return pk, ok
}
