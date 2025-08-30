package config

import (
	"os"
	"strconv"
)

type Config struct {
	RabbitURL   string
	Queue       string
	Exchange    string
	BindKey     string
	Concurrency int
}
  
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func geti(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func Load() Config {
	return Config{
		RabbitURL:   getenv("RABBIT_URL", "amqp://guest:guest@localhost:5672/"),
		Queue:       getenv("RABBIT_QUEUE", "greetq"),
		Exchange:    getenv("RABBIT_EXCHANGE", "congrats.events"),
		BindKey:     getenv("RABBIT_BIND_KEY", "greeting.created"),
		Concurrency: geti("RABBIT_CONCURRENCY", 4),
	}
}
