package jwt

import (
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type JWKStorage interface {
	SaveActiveKey(key jwk.Key, expiry time.Time) error
	SavePreviousKey(key jwk.Key, expiry time.Time) error
	GetActiveKey() (jwk.Key, time.Time, error)
	GetPreviousKeys() ([]KeyWithExpiry, error)
	SetPreviousKeys(keys []KeyWithExpiry) error
}

// KeyWithExpiry is a small struct to hold a JWK key along with its expiration.
type KeyWithExpiry struct {
	Key    jwk.Key
	Expiry time.Time
}

// InMemoryStorage is a trivial in-memory example.
type InMemoryStorage struct {
	mu           sync.RWMutex
	activeKey    KeyWithExpiry
	previousKeys []KeyWithExpiry
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{}
}

func (s *InMemoryStorage) SaveActiveKey(key jwk.Key, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeKey = KeyWithExpiry{Key: key, Expiry: expiry}
	return nil
}

func (s *InMemoryStorage) SavePreviousKey(key jwk.Key, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previousKeys = append(s.previousKeys, KeyWithExpiry{Key: key, Expiry: expiry})
	return nil
}

func (s *InMemoryStorage) GetActiveKey() (jwk.Key, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeKey.Key, s.activeKey.Expiry, nil
}

func (s *InMemoryStorage) GetPreviousKeys() ([]KeyWithExpiry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to avoid direct mutation
	keysCopy := make([]KeyWithExpiry, len(s.previousKeys))
	copy(keysCopy, s.previousKeys)
	return keysCopy, nil
}

func (s *InMemoryStorage) SetPreviousKeys(keys []KeyWithExpiry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previousKeys = keys
	return nil
}
