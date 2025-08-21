package security

import (
	"crypto/rand"
	"encoding/base64"
)

func NewRefreshToken() (string, error) {
	b := make([]byte, 32) // 256 бит
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func NewID() (string, error) { // для JTI/Family
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
