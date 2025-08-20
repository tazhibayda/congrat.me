package queue

import (
	"context"
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

type Publisher struct {
	conn *amqp.Connection
	ch   *amqp.Channel
}

func NewPublisher(url string) (*Publisher, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	return &Publisher{conn: conn, ch: ch}, nil
}

func (p *Publisher) Close() {
	p.ch.Close()
	p.conn.Close()
}

func (p *Publisher) Publish(ctx context.Context, exchange, key string, event interface{}, reqID string) error {
	body, _ := json.Marshal(event)
	return p.ch.PublishWithContext(ctx, exchange, key, false, false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
			MessageId:   uuid.NewString(),
			Timestamp:   time.Now(),
			Headers: amqp.Table{
				"X-Request-ID": reqID,
			},
		})
}

type UserRegistered struct {
	UserID primitive.ObjectID `json:"user_id"`
	Email  string             `json:"email"`
	Name   string             `json:"name"`
}
type UserLoggedIn struct {
	UserID primitive.ObjectID `json:"user_id"`
	Email  string             `json:"email"`
}
