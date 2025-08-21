package security

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Claims struct {
	UID   string `json:"uid"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func MakeAccess(secret, uid, email string, ttl time.Duration) (string, error) {
	c := Claims{
		UID: uid, Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			Subject:   uid,
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return t.SignedString([]byte(secret))
}

func ParseAccess(secret, token string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}

func MakeAccessRS256(km *KeyManager, uid, email string, ttl time.Duration) (string, error) {
	c := Claims{
		UID: uid, Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			Subject:   uid,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = km.Active.Kid
	return token.SignedString(km.Active.Private)
}
