package jwt

import (
	"sync"
	"time"

	"gorm.io/gorm"
)

// KeyEntry represents an encryption key with associated metadata.
type KeyEntry struct {
	ID     uint      `gorm:"primaryKey"` // For GORM
	Key    []byte
	Info   []byte
	Expiry time.Time
}

// KeyStore defines methods for persisting and retrieving key entries.
type KeyStore interface {
	SaveKey(entry KeyEntry) error
	GetAllKeys() ([]KeyEntry, error)
}

// InMemoryKeyStore is an in-memory implementation of KeyStore.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys []KeyEntry
}

// NewInMemoryKeyStore initializes a new in-memory key store.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{}
}

// SaveKey saves a key entry into memory.
func (s *InMemoryKeyStore) SaveKey(entry KeyEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, entry)
	return nil
}

// GetAllKeys retrieves all saved key entries.
func (s *InMemoryKeyStore) GetAllKeys() ([]KeyEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]KeyEntry, len(s.keys))
	copy(copied, s.keys)
	return copied, nil
}

// GormKeyStore uses GORM to persist key entries.
type GormKeyStore struct {
	db *gorm.DB
}

// NewGormKeyStore initializes a new GormKeyStore and migrates the KeyEntry schema.
func NewGormKeyStore(db *gorm.DB) *GormKeyStore {
	db.AutoMigrate(&KeyEntry{})
	return &GormKeyStore{db: db}
}

// SaveKey saves a key entry using GORM.
func (s *GormKeyStore) SaveKey(entry KeyEntry) error {
	return s.db.Create(&entry).Error
}

// GetAllKeys retrieves all saved key entries using GORM.
func (s *GormKeyStore) GetAllKeys() ([]KeyEntry, error) {
	var keys []KeyEntry
	err := s.db.Find(&keys).Error
	return keys, err
}
