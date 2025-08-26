package repo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Store struct {
	Client       *mongo.Client
	DB           *mongo.Database
	colThreads   *mongo.Collection
	colGreetings *mongo.Collection
}

func NewStore(ctx context.Context, uri, dbname string) (*Store, error) {
	cli, err := mongo.Connect(ctx, options.Client().
		ApplyURI(uri).
		SetRetryWrites(true).
		SetMaxPoolSize(50),
	)
	if err != nil {
		return nil, err
	}
	if err := cli.Ping(ctx, nil); err != nil {
		return nil, err
	}
	db := cli.Database(dbname)
	return &Store{
		Client:       cli,
		DB:           db,
		colThreads:   db.Collection("threads"),
		colGreetings: db.Collection("greetings"),
	}, nil
}

func (s *Store) Close(ctx context.Context) error { return s.Client.Disconnect(ctx) }

// Создаём индексы для производительности и целостности.
// ВАЖНО: TTL-индекс по `expires_at` удалит документ автоматически, если поле есть.
// Для "навсегда" просто не заполняем `expires_at`.
func (s *Store) EnsureIndexes(ctx context.Context) error {
	// threads
	_, err := s.colThreads.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "slug", Value: 1}},
			Options: options.Index().SetUnique(true).SetName("uniq_slug"),
		},
		{
			Keys:    bson.D{{Key: "owner_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("owner_created_desc"),
		},
		{
			// TTL: удаляем документ, когда наступает expires_at (expireAfterSeconds=0)
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetName("ttl_expire"),
		},
	})
	if err != nil {
		return err
	}

	// greetings
	_, err = s.colGreetings.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "thread_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("thread_created_desc"),
		},
		{
			Keys:    bson.D{{Key: "created_at", Value: -1}},
			Options: options.Index().SetName("created_desc"),
		},
		// Можно добавить текстовый индекс для будущего поиска по сообщению:
		// { Keys: bson.D{{Key: "message", Value: "text"}}, Options: options.Index().SetName("message_text") },
	})
	return err
}

func IsDup(err error) bool {
	var we mongo.WriteException
	if errors.As(err, &we) {
		for _, e := range we.WriteErrors {
			if e.Code == 11000 {
				return true
			}
		}
	}
	var ce *mongo.CommandError
	if errors.As(err, &ce) && ce.Code == 11000 {
		return true
	}
	return false
}
