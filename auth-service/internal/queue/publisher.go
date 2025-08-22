package queue

import (
	"context"
	_ "encoding/json"
	"go.mongodb.org/mongo-driver/bson/primitive"
	_ "time"

	_ "github.com/google/uuid"
	_ "github.com/rabbitmq/amqp091-go"
)

type Publisher interface {
	Publish(ctx context.Context, exchange, key string, event any, reqID string) error
	Close() error
}

type NoopPub struct{}

func NewNoop() Publisher { return NoopPub{} }

func (NoopPub) Publish(ctx context.Context, exchange, key string, event any, reqID string) error {
	return nil
}
func (NoopPub) Close() error { return nil }

type UserRegistered struct {
	UserID primitive.ObjectID `json:"user_id"`
	Email  string             `json:"email"`
	Name   string             `json:"name"`
}
type UserLoggedIn struct {
	UserID primitive.ObjectID `json:"user_id"`
	Email  string             `json:"email"`
}
