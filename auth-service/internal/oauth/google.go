package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	ggoogle "golang.org/x/oauth2/google"
)

type GoogleOAuth struct {
	cfg      *oauth2.Config
	stateKey []byte
}

func NewGoogle(clientID, clientSecret, redirectURI, stateSecret string) *GoogleOAuth {
	return &GoogleOAuth{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Scopes: []string{
				"openid", "email", "profile",
			},
			Endpoint: ggoogle.Endpoint,
		},
		stateKey: []byte(stateSecret),
	}
}

// HMAC(state) для защиты от CSRF
func (g *GoogleOAuth) MakeState(raw string) string {
	mac := hmac.New(sha256.New, g.stateKey)
	mac.Write([]byte(raw))
	sig := mac.Sum(nil)
	return raw + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (g *GoogleOAuth) VerifyState(got string) bool {
	i := -1
	for idx := range got {
		if got[idx] == '.' {
			i = idx
			break
		}
	}
	if i < 0 {
		return false
	}
	raw := got[:i]
	sigb, err := base64.RawURLEncoding.DecodeString(got[i+1:])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, g.stateKey)
	mac.Write([]byte(raw))
	return hmac.Equal(mac.Sum(nil), sigb)
}

func (g *GoogleOAuth) AuthURL(state string) string {
	// можно добавить параметр nonce, но для начала достаточно state
	return g.cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

type GoogleUser struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

func (g *GoogleOAuth) ExchangeAndVerify(ctx context.Context, code string, expectedAud string) (*GoogleUser, error) {
	tok, err := g.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	// id_token — JWT от Google
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("no id_token")
	}

	// Минимальная проверка: просто распарсить и проверить aud == clientID и iss
	// (Для прод лучше скачивать Google certs и verify подпись. Для pet-проекта — достаточно проверки полей)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation()) // без подписи
	claims := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(rawIDToken, claims); err != nil {
		return nil, fmt.Errorf("parse id_token: %w", err)
	}
	iss, _ := claims["iss"].(string)
	aud, _ := claims["aud"].(string)
	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	sub, _ := claims["sub"].(string)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)

	if iss != "https://accounts.google.com" && iss != "accounts.google.com" {
		return nil, errors.New("bad iss")
	}
	if aud != expectedAud {
		return nil, errors.New("bad aud")
	}
	if email == "" || sub == "" {
		return nil, errors.New("missing email/sub")
	}

	return &GoogleUser{
		Sub: sub, Email: email, EmailVerified: emailVerified, Name: name, Picture: picture,
	}, nil
}
