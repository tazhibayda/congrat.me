package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port             string
	MongoURI         string
	MongoDB          string
	JWTSecret        string
	RefreshTTLDays   int
	RedisAddr        string
	RateLimitPerMin  int
	RabbitURL        string
	JWTActiveKID     string
	JWTActiveKeyPath string
	JWTNextKID       string
	JWTNextKeyPath   string
}

func Load() Config {
	return Config{
		Port:             getenv("APP_PORT", "8080"),
		MongoURI:         getenv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:          getenv("MONGO_DB", "auth_db"),
		JWTSecret:        getenv("JWT", "default_secret_key"),
		RefreshTTLDays:   atoi(getenv("REFRESH_TTL_DAYS", "14")),
		RedisAddr:        getenv("REDIS_ADDR", "localhost:6379"),
		RateLimitPerMin:  atoi(getenv("RATE_LIMIT_PER_MIN", "5")),
		RabbitURL:        getenv("RABBIT_URL", "amqp://guest:guest@localhost:5672/"),
		JWTActiveKID:     getenv("JWT_ACTIVE_KID", "kid-active"),
		JWTActiveKeyPath: getenv("JWT_ACTIVE_PRIVATE_PATH", "./keys/active.pem"),
		JWTNextKID:       getenv("JWT_NEXT_KID", ""),
		JWTNextKeyPath:   getenv("JWT_NEXT_PRIVATE_PATH", "")}
}

func atoi(s string) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return 0
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
