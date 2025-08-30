package queue

import (
	"context"
	"fmt"
	"sync"

	amqp "github.com/rabbitmq/amqp091-go"
)

type Consumer struct {
	conn *amqp.Connection
	ch   *amqp.Channel
	q    string
}

func NewConsumer(url, exchange, queue, key string) (*Consumer, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("dial rabbit: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("open channel: %w", err)
	}

	// гарантируем, что exchange/queue существуют и связаны
	if err := ch.ExchangeDeclare(exchange, "topic", true, false, false, false, nil); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("declare exchange: %w", err)
	}
	qd, err := ch.QueueDeclare(queue, true, false, false, false, nil)
	if err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("declare queue: %w", err)
	}
	if err := ch.QueueBind(qd.Name, key, exchange, false, nil); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("bind queue: %w", err)
	}

	return &Consumer{conn: conn, ch: ch, q: qd.Name}, nil
}

func (c *Consumer) Close() {
	if c == nil {
		return
	}
	if c.ch != nil {
		_ = c.ch.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func (c *Consumer) Consume(ctx context.Context, workers int, handle func([]byte) error) error {
	if c == nil || c.ch == nil {
		return fmt.Errorf("consumer is not initialized")
	}
	if workers <= 0 {
		workers = 1
	}

	// ограничим префетч, чтобы не перегружать память
	if err := c.ch.Qos(50, 0, false); err != nil {
		return fmt.Errorf("qos: %w", err)
	}
	msgs, err := c.ch.Consume(c.q, "", false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("consume: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case d, ok := <-msgs:
					if !ok {
						return // канал закрыт — выходим из воркера
					}
					if err := handle(d.Body); err != nil {
						// повторная доставка (requeue=true) — простой ретрай
						d.Nack(false, true)
						continue
					}
					d.Ack(false)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// ждём остановки
	<-ctx.Done()
	wg.Wait()
	return nil
}
