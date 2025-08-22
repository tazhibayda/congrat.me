package http_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/tazhibayda/auth-service/internal/log"
	"github.com/tazhibayda/auth-service/internal/queue"
	_ "net/http"
	_ "net/http/httptest"
	"os"
	"testing"
	_ "time"

	"github.com/gin-gonic/gin"
	_ "github.com/tazhibayda/auth-service/internal/config"
	http "github.com/tazhibayda/auth-service/internal/http"
	"github.com/tazhibayda/auth-service/internal/oauth"
	"github.com/tazhibayda/auth-service/internal/repo"
	"github.com/tazhibayda/auth-service/internal/security"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
)

type testEnv struct {
	T      *testing.T
	Ctx    context.Context
	Mongo  *mongodb.MongoDBContainer
	Store  *repo.Store
	Keys   *security.KeyManager
	Router *gin.Engine
}

func genRSA(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// сохраним во временный файл в формате PKCS1
	tmp, err := os.CreateTemp("", "rsa_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	_ = pem.Encode(tmp, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return k, tmp.Name()
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	// поднять Mongo (testcontainers)
	mc, err := mongodb.RunContainer(ctx,
		testcontainers.WithImage("mongo:6"),
	)
	if err != nil {
		t.Fatalf("mongo container: %v", err)
	}

	uri, err := mc.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("mongo uri: %v", err)
	}

	// init zap logger for tests (dev mode)
	if _, err := log.Init(false); err != nil {
		t.Fatalf("log init: %v", err)
	}

	store, err := repo.NewStore(ctx, uri, "auth_test")
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	if err := store.EnsureUserIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureRefreshIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureEmailTokenIndexes(ctx); err != nil {
		t.Fatal(err)
	}

	// RSA key manager (active + next)
	_, activePath := genRSA(t)
	_, nextPath := genRSA(t)
	km, err := security.NewKeyManager("kidA", activePath, "kidN", nextPath)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	pub := queue.NewNoop()

	// собрать Handler (Redis/Rabbit не нужны → nil)
	h := http.NewHandler(store, "", 14, nil, 0, pub, km) // jwtSecret не используется; rlPerMin большой
	// OAuth можно мокать: h.Google = oauth.NewGoogle("id","sec","http://localhost/cb","state") — но для этих тестов не нужен
	h.Google = &oauth.GoogleOAuth{} // заглушка

	// gin в test‑режиме
	gin.SetMode(gin.TestMode)
	r := http.NewRouter(h) // маршруты + middleware

	return &testEnv{T: t, Ctx: ctx, Mongo: mc, Store: store, Keys: km, Router: r}
}

func (e *testEnv) Close() {
	if e.Store != nil {
		_ = e.Store.Client.Disconnect(e.Ctx)
	}
	if e.Mongo != nil {
		_ = e.Mongo.Terminate(e.Ctx)
	}
}
