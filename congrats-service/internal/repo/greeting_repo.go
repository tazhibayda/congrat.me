package repo

import (
	"context"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"

	"github.com/tazhibayda/congrats-service/internal/domain"
	"go.mongodb.org/mongo-driver/bson"
	_ "go.mongodb.org/mongo-driver/mongo"
	_ "go.mongodb.org/mongo-driver/mongo/options"
)

func (s *Store) AddGreeting(ctx context.Context, g *domain.Greeting) error {
	g.CreatedAt = time.Now().UTC()
	res, err := s.colGreetings.InsertOne(ctx, g)
	if oid, ok := res.InsertedID.(primitive.ObjectID); ok {
		g.ID = oid
	}
	return err
}

func (s *Store) ListGreetings(ctx context.Context, threadID primitive.ObjectID, limit, skip int) ([]domain.Greeting, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if skip < 0 {
		skip = 0
	}
	cur, err := s.colGreetings.Find(ctx,
		bson.M{"thread_id": threadID},
		optionsFind().SetLimit(int64(limit)).SetSkip(int64(skip)).
			SetSort(bson.D{{Key: "created_at", Value: 1}}), // по возрастанию времени
	)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []domain.Greeting
	for cur.Next(ctx) {
		var g domain.Greeting
		if err := cur.Decode(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, cur.Err()
}

// Используем при ручном удалении треда (TTL Mongo сам удалит тред, но поздравления — нет):
func (s *Store) DeleteGreetingsByThread(ctx context.Context, threadID string) (int64, error) {
	res, err := s.colGreetings.DeleteMany(ctx, bson.M{"thread_id": threadID})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}
