package repo

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/tazhibayda/congrats-service/internal/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	ErrSlugExists = errors.New("slug already exists")
	ErrNotFound   = errors.New("not found")
)

func normalizeSlug(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func (s *Store) CreateThread(ctx context.Context, t *domain.Thread) error {
	t.Slug = normalizeSlug(t.Slug)
	now := time.Now().UTC()
	t.CreatedAt = now

	if t.TTLDays > 0 {
		exp := now.Add(time.Duration(t.TTLDays) * 24 * time.Hour).UTC()
		t.ExpiresAt = &exp
	} else {
		t.ExpiresAt = nil // "навсегда" — без TTL-поля
	}

	_, err := s.colThreads.InsertOne(ctx, t)
	if IsDup(err) {
		return ErrSlugExists
	}
	return err
}

// Находим по slug. Документы с истёкшим TTL Mongo удалит сам;
// но между истечением и джобой TTL документ может вернуться — это ок.
func (s *Store) FindThreadBySlug(ctx context.Context, slug string) (*domain.Thread, error) {
	slug = normalizeSlug(slug)
	var t domain.Thread
	err := s.colThreads.FindOne(ctx, bson.M{"slug": slug}).Decode(&t)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &t, err
}

type ListParams struct {
	Limit int
	Skip  int
}

func (s *Store) ListThreadsByOwner(ctx context.Context, owner string, p ListParams) ([]domain.Thread, error) {
	if p.Limit <= 0 || p.Limit > 200 {
		p.Limit = 50
	}
	if p.Skip < 0 {
		p.Skip = 0
	}

	cur, err := s.colThreads.Find(ctx,
		bson.M{"owner_id": owner},
		optionsFind().SetLimit(int64(p.Limit)).SetSkip(int64(p.Skip)).
			SetSort(bson.D{{Key: "created_at", Value: -1}}),
	)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []domain.Thread
	for cur.Next(ctx) {
		var t domain.Thread
		if err := cur.Decode(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, cur.Err()
}

func (s *Store) DeleteThreadByOwner(ctx context.Context, slug, owner string) (bool, error) {
	res, err := s.colThreads.DeleteOne(ctx, bson.M{"slug": normalizeSlug(slug), "owner_id": owner})
	return res.DeletedCount == 1, err
}

// маленький хелпер — чтобы не тащить import options в каждую функцию
func optionsFind() *mongo.FindOptions { return &mongo.FindOptions{} }
