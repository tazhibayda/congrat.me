package repo

import (
	"context"
	"github.com/tazhibayda/auth-service/internal/domain"
	"github.com/tazhibayda/auth-service/internal/helper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"time"
)

type Store struct {
	Client *mongo.Client
	DB     *mongo.Database
}

func NewStore(ctx context.Context, uri, dbname string) (*Store, error) {
	cli, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	return &Store{Client: cli, DB: cli.Database(dbname)}, nil
}

func (s *Store) EnsureUserIndexes(ctx context.Context) error {
	coll := s.DB.Collection("users")
	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return err
}

func (s *Store) CreateUser(ctx context.Context, u *domain.User) error {
	sp, ctx := tracer.StartSpanFromContext(ctx, "mongo.insert_user",
		tracer.Tag("collection", "users"),
		tracer.Tag("email_hash", helper.Hash8(u.Email)),
	)
	defer sp.Finish()

	u.CreatedAt = time.Now().UTC()
	_, err := s.DB.Collection("users").InsertOne(ctx, u)
	if err != nil {
		sp.SetTag("error", err)
	}
	return err
}

func (s *Store) FindUserByID(ctx context.Context, id primitive.ObjectID) (*domain.User, error) {
	sp, ctx := tracer.StartSpanFromContext(ctx, "mongo.find_user_by_id",
		tracer.Tag("collection", "users"),
		tracer.Tag("user_id", id),
	)
	defer sp.Finish()

	var u domain.User
	err := s.DB.Collection("users").FindOne(ctx, bson.M{"_id": id}).Decode(&u)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		sp.SetTag("error", err)
		return nil, err
	}
	return &u, err
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	span, ctx := tracer.StartSpanFromContext(ctx, "mongo.find_user",
		tracer.Tag("collection", "users"),
		tracer.Tag("email", email),
	)
	defer span.Finish()
	var u domain.User
	err := s.DB.Collection("users").
		FindOne(ctx, bson.M{"email": email}).Decode(&u)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		span.SetTag("error", err)
		return nil, err
	}
	return &u, err
}

func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.Client.Ping(ctx, nil)
}

func (s *Store) Close(ctx context.Context) error {
	return s.Client.Disconnect(ctx)
}
