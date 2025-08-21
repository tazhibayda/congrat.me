package main

import (
	"context"
	"errors"
	docs "github.com/tazhibayda/auth-service/docs"
	"github.com/tazhibayda/auth-service/internal/config"
	api "github.com/tazhibayda/auth-service/internal/http"
	"github.com/tazhibayda/auth-service/internal/log"
	"github.com/tazhibayda/auth-service/internal/metrics"
	"github.com/tazhibayda/auth-service/internal/queue"
	"github.com/tazhibayda/auth-service/internal/repo"
	"github.com/tazhibayda/auth-service/internal/security"
	"go.uber.org/zap"
	_ "gopkg.in/DataDog/dd-trace-go.v1/contrib/gin-gonic/gin"
	gintrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gin-gonic/gin"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// @title Auth Service API
// @version 1.0
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {

	tracer.Start(
		tracer.WithEnv("dev"),
		tracer.WithService("auth-service"),
		tracer.WithServiceVersion("0.1.0"),
		tracer.WithRuntimeMetrics(),
	)
	defer tracer.Stop()

	if cleanup, err := log.Init(false); err != nil {
		panic(err)
	} else {
		defer cleanup()
	}

	cfg := config.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	docs.SwaggerInfo.BasePath = "/"
	metrics.MustRegister()

	store, err := repo.NewStore(ctx, cfg.MongoURI, cfg.MongoDB)
	if err != nil {
		log.L.Fatal("mongo connect failed", zap.Error(err))
	}
	defer store.Close(context.Background())

	if err := store.EnsureUserIndexes(ctx); err != nil {
		log.L.Fatal("ensure indexes failed", zap.Error(err))
	}
	if err := store.EnsureRefreshIndexes(ctx); err != nil {
		log.L.Fatal("ensure refresh indexes failed", zap.Error(err))
	}

	log.L.Info("mongo connected and indexes ensured",
		zap.String("db", cfg.MongoDB),
		zap.String("uri", cfg.MongoURI),
	)

	rds := repo.NewRedis(cfg.RedisAddr)
	{
		rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer rcancel()
		if err := rds.Ping(rctx); err != nil {
			log.L.Fatal("redis ping failed", zap.Error(err), zap.String("addr", cfg.RedisAddr))
		}
	}
	defer rds.Close()
	log.L.Info("connected to Redis ", zap.String("addr", cfg.RedisAddr))

	pub, err := queue.NewPublisher(cfg.RabbitURL)
	if err != nil {
		log.L.Fatal("rabbit connect", zap.Error(err))
	}
	defer pub.Close()

	km, err := security.NewKeyManager(cfg.JWTActiveKID, cfg.JWTActiveKeyPath, cfg.JWTNextKID, cfg.JWTNextKeyPath)
	if err != nil {
		log.L.Fatal("keys", zap.Error(err))
	}

	h := api.NewHandler(store, cfg.JWTSecret, cfg.RefreshTTLDays, rds, cfg.RateLimitPerMin, pub, km)
	r := api.NewRouter(h)
	r.Use(gintrace.Middleware("auth-service"))

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.L.Error("http server error", zap.Error(err))
		}
	}()

	log.L.Info("auth-service listening", zap.String("addr", srv.Addr))

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	log.L.Info("shutdown signal received", zap.String("signal", sig.String()))

	shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shCancel()

	if err := srv.Shutdown(shCtx); err != nil {
		log.L.Error("server shutdown error", zap.Error(err))
	} else {
		log.L.Info("server stopped gracefully")
	}
}
