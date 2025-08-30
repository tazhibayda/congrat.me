package queue

import (
	"context"
	"encoding/json"
	"time"

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
func (p *Publisher) Close() { _ = p.ch.Close(); _ = p.conn.Close() }

func (p *Publisher) Publish(ctx context.Context, exchange, key string, headers map[string]interface{}, v any) error {
	body, _ := json.Marshal(v)
	return p.ch.PublishWithContext(ctx, exchange, key, false, false, amqp.Publishing{
		ContentType: "application/json",
		Body:        body,
		Timestamp:   time.Now(),
		Headers:     amqp.Table(headers),
	})
}

type GreetingCreated struct {
	ThreadID string `json:"thread_id"`
	Slug     string `json:"slug"`
	Author   string `json:"author"`
}
