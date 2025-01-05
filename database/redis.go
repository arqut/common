package database

import (
	"fmt"

	"github.com/arqut/common/system"
	"github.com/redis/go-redis/v9"
)

var (
	RedisClient *redis.Client
)

func InitRedisClient() {
	addr := fmt.Sprintf("%s:6379", system.Env("REDIS_HOST", "localhost"))
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     addr,                         // Redis server address
		Password: system.Env("REDIS_PASS", ""), // No password set
		DB:       system.EnvInt("REDIS_DB", 1), // use default DB
	})
	system.Logger.Infof("Init redis client: '%s'\n", addr)
}
