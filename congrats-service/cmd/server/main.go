package main

import (
	"context"
	docs "github.com/tazhibayda/congrats-service/docs"
	"github.com/tazhibayda/congrats-service/internal/config"
	httpapi "github.com/tazhibayda/congrats-service/internal/http"
	"github.com/tazhibayda/congrats-service/internal/queue"
	"github.com/tazhibayda/congrats-service/internal/repo"
	"github.com/tazhibayda/congrats-service/internal/security"
	"log"
	"time"
)

// @title Congrats API
// @version 0.1.0
// @description API for creating greeting threads and messages.
// @schemes http https
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, err := repo.NewStore(ctx, cfg.MongoURI, cfg.MongoDB)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close(context.Background())

	if err := store.EnsureIndexes(ctx); err != nil {
		log.Fatal(err)
	}

	pub, err := queue.NewPublisher(cfg.RabbitURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pub.Close()

	jwks := security.NewFetcher(cfg.AuthJWKSURL, time.Duration(cfg.JWKSCacheSeconds)*time.Second)

	docs.SwaggerInfo.BasePath = "/"

	h := httpapi.NewHandler(store, pub)
	r := httpapi.NewRouter(h, jwks)

	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
