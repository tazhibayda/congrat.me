package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/tazhibayda/notify-service/internal/config"
	"github.com/tazhibayda/notify-service/internal/mail"
	"github.com/tazhibayda/notify-service/internal/queue"
)

func main() {
	cfg := config.Load()

	cons, err := queue.NewConsumer(cfg.RabbitURL, cfg.Exchange, cfg.Queue, cfg.BindKey)
	if err != nil {
		log.Fatalf("rabbit consumer init failed: %v", err) // <- не даём программе идти дальше
	}
	defer cons.Close()

	sender := &mail.Sender{}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("notify-service up. url=%s exchange=%s queue=%s key=%s workers=%d",
		cfg.RabbitURL, cfg.Exchange, cfg.Queue, cfg.BindKey, cfg.Concurrency)

	if err := cons.Consume(ctx, cfg.Concurrency, func(b []byte) error {
		// TODO: свой хэндлер
		return sender.SendGreeting("owner@example.com", "New greeting", string(b))
	}); err != nil {
		log.Fatalf("consumer stopped: %v", err)
	}
}
