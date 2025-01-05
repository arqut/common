package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/arqut/common/system"
	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
)

// type wraper struct {
// }

func InitRedisStorage(client *redis.Client) {
	redisClient = client
}

// Set set string value
func Set(key string, value string, expiration ...time.Duration) error {
	return redisClient.Set(context.TODO(), key, value, GetExpiration(expiration...)).Err()
}

// Get get string value
func Get(key string) (string, error) {
	return redisClient.Get(context.TODO(), key).Result()
}

// SetObj set object/struct value
func SetObj(key string, value interface{}, expiration ...time.Duration) error {
	p, err := json.Marshal(value)

	if err != nil {
		return err
	}

	return redisClient.Set(context.TODO(), key, p, GetExpiration(expiration...)).Err()
}

// GetObj get object/struct value
func GetObj(key string, out interface{}) error {
	p, err := redisClient.Get(context.TODO(), key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(p, out)
}

func Del(key string) error {
	return redisClient.Del(context.TODO(), key).Err()
}

func GetExpiration(expiration ...time.Duration) time.Duration {
	if len(expiration) > 0 {
		return expiration[0]
	}

	if str := system.Env("CACHE_DURATION"); str != "" {
		if duration, err := time.ParseDuration(str); err == nil {
			return duration
		}
	}

	return time.Hour
}
