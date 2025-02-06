package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/arqut/common/database"
	"github.com/arqut/common/system"
	"github.com/arqut/common/utils"
	"github.com/redis/go-redis/v9"
)

var (
	instance *RedisCache
	// redisClient *redis.Client
)

type RedisCache struct {
	redisClient       *redis.Client
	defaultExpiration time.Duration
}

func InitRedisCache(redisClient *redis.Client, defaultExpiration ...time.Duration) {
	instance = &RedisCache{
		redisClient:       redisClient,
		defaultExpiration: getExpiration(defaultExpiration...),
	}
}

func NewRedisCache(connString string, defaultExpiration ...time.Duration) (*RedisCache, error) {
	redisClient, err := database.NewRedisClient(connString)
	if err != nil {
		return nil, err
	}

	return &RedisCache{
		redisClient:       redisClient,
		defaultExpiration: getExpiration(defaultExpiration...),
	}, nil
}

// Set set string value
func Set(key string, value string, expiration ...time.Duration) error {
	return instance.Set(key, value, expiration...)
}

// Get get string value
func Get(key string) (string, error) {
	return instance.Get(key)
}

// SetObj set object/struct value
func SetObj(key string, value interface{}, expiration ...time.Duration) error {
	return instance.SetObj(key, value, expiration...)
}

// GetObj get object/struct value
func GetObj(key string, out interface{}) error {
	return instance.GetObj(key, out)
}

func Del(key string) error {
	return instance.Del(key)
}

func getExpiration(expiration ...time.Duration) time.Duration {
	if len(expiration) > 0 {
		return expiration[0]
	}

	if str := system.Env("CACHE_DURATION"); str != "" {
		if duration, err := utils.ParseDuration(str); err == nil {
			return duration
		}
	}

	return time.Hour
}

func (ins *RedisCache) Set(key string, value string, expiration ...time.Duration) error {
	return ins.redisClient.Set(context.TODO(), key, value, ins.getExpiration(expiration...)).Err()
}

func (ins *RedisCache) Get(key string) (string, error) {
	return ins.redisClient.Get(context.TODO(), key).Result()
}

func (ins *RedisCache) SetObj(key string, value interface{}, expiration ...time.Duration) error {
	p, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return ins.redisClient.Set(context.TODO(), key, p, ins.getExpiration(expiration...)).Err()
}

func (ins *RedisCache) GetObj(key string, out interface{}) error {
	p, err := ins.redisClient.Get(context.TODO(), key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(p, out)
}

func (ins *RedisCache) Del(key string) error {
	return ins.redisClient.Del(context.TODO(), key).Err()
}

func (ins *RedisCache) getExpiration(expiration ...time.Duration) time.Duration {
	if len(expiration) > 0 {
		return expiration[0]
	}

	return ins.defaultExpiration
}
