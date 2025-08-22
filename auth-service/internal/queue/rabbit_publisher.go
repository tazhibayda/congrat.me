package queue

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"time"
)

type RabbitPublisher struct {
	conn *amqp.Connection
	ch   *amqp.Channel
}

func NewRabbit(url, exchange string) (Publisher, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := ch.ExchangeDeclare(
		exchange, "topic", true, false, false, false, nil,
	); err != nil {
		ch.Close()
		conn.Close()
		return nil, err
	}
	return &RabbitPublisher{conn: conn, ch: ch}, nil
}

func (p *RabbitPublisher) Close() error {
	if p == nil {
		return nil
	}
	// закрываем канал и соединение, игнорируя последовательные ошибки
	if p.ch != nil {
		_ = p.ch.Close()
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
	return nil
}

func (p *RabbitPublisher) Publish(ctx context.Context, exchange, key string, event any, reqID string) error {
	// на всякий случай защитимся от nil (в проде используйте Noop вместо nil)
	if p == nil || p.ch == nil {
		return nil
	}

	body, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// чтобы не повиснуть, если брокер тормозит
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}

	return p.ch.PublishWithContext(ctx, exchange, key, false, false, amqp.Publishing{
		ContentType: "application/json",
		Body:        body,
		MessageId:   uuid.NewString(),
		Timestamp:   time.Now(),
		Headers: amqp.Table{
			"X-Request-ID": reqID,
		},
	})
}
