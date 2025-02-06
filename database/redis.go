package database

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/arqut/common/system"
	"github.com/redis/go-redis/v9"
)

var (
	RedisClient *redis.Client
)

// InitRedisClient initializes a Redis client using env. connection string `REDIS_CONN`
func InitRedisClient(connStr ...string) (err error) {
	RedisClient, err = NewRedisClient(system.Env("REDIS_CONN", "localhost"))
	return
}

// InitRedisClient initializes a Redis client using optional "host:port@db@password" format.
// - `port`, `db`, and `password` are optional.
// - Defaults: port=6379, db=1, password=""
func NewRedisClient(connStr string) (*redis.Client, error) {
	var db int
	var addr, pass string

	// Split at '@' to extract host:port, db, and password
	parts := strings.SplitN(connStr, "@", 3)
	addr = parts[0] // "host:port"

	// Defaults
	db = 1
	pass = ""

	// Handle optional db and password
	if len(parts) > 1 && parts[1] != "" {
		parsedDB, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid database index: %w", err)
		}
		db = parsedDB
	}
	if len(parts) > 2 {
		pass = parts[2] // Password can be empty
	}

	// Ensure host has a port
	if !strings.Contains(addr, ":") {
		addr += ":6379" // Default Redis port
	}

	client := redis.NewClient(&redis.Options{
		DB:       db,   // use default DB
		Addr:     addr, // Redis server address
		Password: pass, // No password set
	})

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: '%s@%d', error: %w", addr, db, err)
	} else {
		system.Logger.Infof("Connect to redis: '%s@%d'", addr, db)
	}

	return client, nil
}
