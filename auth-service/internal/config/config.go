package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port           string
	MongoURI       string
	MongoDB        string
	JWTSecret      string
	RefreshTTLDays int
}

func Load() Config {
	return Config{
		Port:           getenv("APP_PORT", "8080"),
		MongoURI:       getenv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:        getenv("MONGO_DB", "auth_db"),
		JWTSecret:      getenv("JWT", "default_secret_key"),
		RefreshTTLDays: atoi(getenv("REFRESH_TTL_DAYS", "14")),
	}
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
