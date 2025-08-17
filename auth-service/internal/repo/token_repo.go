package repo

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RefreshToken struct {
	ID        interface{}        `bson:"_id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id"`
	TokenHash string             `bson:"token_hash"` // sha256(base64url(refresh))
	ExpiresAt time.Time          `bson:"expires_at"`
	Revoked   bool               `bson:"revoked"`
	CreatedAt time.Time          `bson:"created_at"`
}

func (s *Store) EnsureRefreshIndexes(ctx context.Context) error {
	coll := s.DB.Collection("refresh_tokens")

	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}); err != nil {
		return err
	}

	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "token_hash", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return err
}

func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Store) SaveRefresh(ctx context.Context, userID primitive.ObjectID, plain string, ttl time.Duration) error {
	rt := RefreshToken{
		UserID:    userID,
		TokenHash: hashToken(plain),
		ExpiresAt: time.Now().Add(ttl).UTC(),
		Revoked:   false,
		CreatedAt: time.Now().UTC(),
	}
	_, err := s.DB.Collection("refresh_tokens").InsertOne(ctx, rt)
	return err
}

func (s *Store) FindValidRefresh(ctx context.Context, plain string) (*RefreshToken, error) {
	var rt RefreshToken
	err := s.DB.Collection("refresh_tokens").
		FindOne(ctx, bson.M{
			"token_hash": hashToken(plain),
			"revoked":    false,
			"expires_at": bson.M{"$gt": time.Now().UTC()},
		}).Decode(&rt)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &rt, err
}

func (s *Store) RevokeRefresh(ctx context.Context, plain string) error {
	_, err := s.DB.Collection("refresh_tokens").
		UpdateOne(ctx, bson.M{"token_hash": hashToken(plain)}, bson.M{"$set": bson.M{"revoked": true}})
	return err
}
