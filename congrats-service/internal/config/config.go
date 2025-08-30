package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port             string
	MongoURI         string
	MongoDB          string
	AuthJWKSURL      string
	JWKSCacheSeconds int
	RabbitURL        string
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func geti(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func Load() Config {
	return Config{
		Port:             getenv("APP_PORT", "8081"),
		MongoURI:         getenv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:          getenv("MONGO_DB", "congrats_db"),
		AuthJWKSURL:      getenv("AUTH_JWKS_URL", "https://auth.tazhibayda.tech/.well-known/jwks.json"),
		JWKSCacheSeconds: geti("JWKS_CACHE_SECONDS", 300),
		RabbitURL:        getenv("RABBIT_URL", "amqp://guest:guest@localhost:5672/"),
	}
}
