package repo

import (
	"context"
	"github.com/go-redis/redis/v8"
)

type Redis struct{ C *redis.Client }

func NewRedis(addr string) *Redis {
	return &Redis{C: redis.NewClient(&redis.Options{Addr: addr})}
}

func (r *Redis) Ping(ctx context.Context) error { return r.C.Ping(ctx).Err() }
func (r *Redis) Close() error                   { return r.C.Close() }
