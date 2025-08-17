package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tazhibayda/auth-service/internal/config"
	api "github.com/tazhibayda/auth-service/internal/http"
	"github.com/tazhibayda/auth-service/internal/repo"
)

func main() {
	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	store, err := repo.NewStore(ctx, cfg.MongoURI, cfg.MongoDB)
	if err != nil {
		if err := store.EnsureUserIndexes(ctx); err != nil {
			log.Fatalf("ensure indexes: %v", err)
		}
		if err := store.EnsureRefreshIndexes(ctx); err != nil {
			log.Fatalf("ensure refresh indexes: %v", err)
		}
		log.Fatalf("mongo connect: %v", err)
	}
	defer store.Close(context.Background())

	h := api.NewHandler(store, cfg.JWTSecret, cfg.RefreshTTLDays)
	r := api.NewRouter(h)

	srvErr := make(chan error, 1)
	go func() { srvErr <- r.Run(":" + cfg.Port) }()

	log.Printf("auth-service listening on :%s", cfg.Port)

	// graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-sig:
		log.Printf("signal: %s, shutting down", s)
	case err := <-srvErr:
		log.Printf("server error: %v", err)
	}
}
