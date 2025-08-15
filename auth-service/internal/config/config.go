package config

import "os"

type Config struct {
	Port     string
	MongoURI string
	MongoDB  string
}

func Load() Config {
	return Config{
		Port:     getenv("APP_PORT", "8080"),
		MongoURI: getenv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:  getenv("MONGO_DB", "auth_db"),
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
