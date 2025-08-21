package repo

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RefreshToken struct {
	ID            interface{}        `bson:"_id,omitempty"`
	UserID        primitive.ObjectID `bson:"user_id"`
	TokenHash     string             `bson:"token_hash"` // sha256(base64url)
	FamilyID      string             `bson:"family_id"`  // uuid на первую выдачу (логин)
	ParentJTI     string             `bson:"parent_jti"` // кто породил (для цепочки)
	JTI           string             `bson:"jti"`        // uuid текущего refresh
	ReplacedByJTI string             `bson:"replaced_by_jti,omitempty"`
	ExpiresAt     time.Time          `bson:"expires_at"`
	Revoked       bool               `bson:"revoked"`
	RevokedReason string             `bson:"revoked_reason,omitempty"` // "rotation" | "reuse_detected" | "logout"
	CreatedAt     time.Time          `bson:"created_at"`
	LastUsedAt    time.Time          `bson:"last_used_at,omitempty"`
	UA            string             `bson:"ua,omitempty"` // user-agent (опцион.)
	IP            string             `bson:"ip,omitempty"` // ip (опцион.)
}

func (s *Store) EnsureRefreshIndexes(ctx context.Context) error {
	coll := s.DB.Collection("refresh_tokens")

	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}); err != nil {
		return err
	}
	_, _ = coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "family_id", Value: 1}},
	})

	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "token_hash", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return err
}

func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Store) SaveRefresh(ctx context.Context, rt RefreshToken) error {
	sp, ctx := tracer.StartSpanFromContext(ctx, "mongo.save_refresh",
		tracer.Tag("collection", "refresh_tokens"),
		tracer.Tag("user_id", rt.ID),
	)
	defer sp.Finish()

	rt.CreatedAt = time.Now().UTC()
	_, err := s.DB.Collection("refresh_tokens").InsertOne(ctx, rt)
	if err != nil {
		sp.SetTag("error", err)
	}
	return err
}

func (s *Store) FindByPlain(ctx context.Context, plain string) (*RefreshToken, error) {
	sp, ctx := tracer.StartSpanFromContext(ctx, "mongo.find_refresh",
		tracer.Tag("collection", "refresh_tokens"),
	)
	defer sp.Finish()

	var rt RefreshToken
	err := s.DB.Collection("refresh_tokens").
		FindOne(ctx, bson.M{"token_hash": HashToken(plain)}).
		Decode(&rt)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		sp.SetTag("error", err)
		return nil, err
	}
	return &rt, nil
}

func (s *Store) MarkRotated(ctx context.Context, oldJTI, newJTI string) error {
	sp, ctx := tracer.StartSpanFromContext(ctx, "mongo.rotate_refresh",
		tracer.Tag("collection", "refresh_tokens"),
		tracer.Tag("old_jti", oldJTI), tracer.Tag("new_jti", newJTI),
	)
	defer sp.Finish()

	_, err := s.DB.Collection("refresh_tokens").UpdateOne(
		ctx,
		bson.M{"jti": oldJTI},
		bson.M{"$set": bson.M{
			"revoked":         true,
			"revoked_reason":  "rotation",
			"replaced_by_jti": newJTI,
			"last_used_at":    time.Now().UTC(),
		}},
	)
	if err != nil {
		sp.SetTag("error", err)
	}
	return err
}

func (s *Store) RevokeRefresh(ctx context.Context, plain string) error {
	sp, ctx := tracer.StartSpanFromContext(ctx, "mongo.revoke_refresh",
		tracer.Tag("collection", "refresh_tokens"),
	)
	defer sp.Finish()

	_, err := s.DB.Collection("refresh_tokens").
		UpdateOne(ctx, bson.M{"token_hash": HashToken(plain)}, bson.M{"$set": bson.M{"revoked": true}})
	if err != nil {
		sp.SetTag("error", err)
	}

	return err
}

func (s *Store) RevokeFamily(ctx context.Context, familyID string) error {
	sp, ctx := tracer.StartSpanFromContext(ctx, "mongo.revoke_family",
		tracer.Tag("collection", "refresh_tokens"),
		tracer.Tag("family_id", familyID),
	)
	defer sp.Finish()

	_, err := s.DB.Collection("refresh_tokens").UpdateMany(
		ctx,
		bson.M{"family_id": familyID, "revoked": false},
		bson.M{"$set": bson.M{"revoked": true, "revoked_reason": "reuse_detected"}},
	)
	if err != nil {
		sp.SetTag("error", err)
	}
	return err
}
