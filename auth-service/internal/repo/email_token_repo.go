package repo

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"time"
)

type EmailToken struct {
	ID        interface{}        `bson:"_id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id"`
	Token     string             `bson:"token"`      // opaque (random base64url)
	Purpose   string             `bson:"purpose"`    // "verify"
	ExpiresAt time.Time          `bson:"expires_at"` // TTL index по этому полю
	UsedAt    *time.Time         `bson:"used_at,omitempty"`
	CreatedAt time.Time          `bson:"created_at"`
}

func (s *Store) EnsureEmailTokenIndexes(ctx context.Context) error {
	coll := s.DB.Collection("email_tokens")
	// TTL
	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}); err != nil {
		return err
	}
	// token уникальный
	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "token", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return err
}

func (s *Store) CreateEmailToken(ctx context.Context, et EmailToken) error {
	sp, _ := tracer.StartSpanFromContext(ctx, "mongo.email_token.insert",
		tracer.Tag("purpose", et.Purpose),
		tracer.Tag("user_id", et.UserID),
	)
	defer sp.Finish()
	et.CreatedAt = time.Now().UTC()
	_, err := s.DB.Collection("email_tokens").InsertOne(ctx, et)
	if err != nil {
		sp.SetTag("error", err)
	}
	return err
}

func (s *Store) UseEmailToken(ctx context.Context, token, purpose string) (*EmailToken, error) {
	// один раз: вернём и пометим used
	sp, _ := tracer.StartSpanFromContext(ctx, "mongo.email_token.consume",
		tracer.Tag("purpose", purpose),
	)
	defer sp.Finish()

	now := time.Now().UTC()
	res := s.DB.Collection("email_tokens").FindOneAndUpdate(
		ctx,
		bson.M{"token": token, "purpose": purpose, "used_at": bson.M{"$exists": false}, "expires_at": bson.M{"$gt": now}},
		bson.M{"$set": bson.M{"used_at": now}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	var et EmailToken
	if err := res.Decode(&et); err != nil {
		sp.SetTag("error", err)
		return nil, err
	}
	return &et, nil
}
