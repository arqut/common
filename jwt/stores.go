package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"gorm.io/gorm"
)

// KeyEntry represents an encryption key with associated metadata.
type KeyEntry struct {
	ID     uint `gorm:"primaryKey"` // For GORM
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
	sort.Slice(copied[:], func(i, j int) bool {
		return copied[i].Expiry.Before(copied[j].Expiry)
	})
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
	err := s.db.Order("expiry DESC").Limit(3).Find(&keys).Error
	return keys, err
}

type RemoteStore struct {
	remoteURL string
	apiKey    string
	client    *http.Client

	cache     []KeyEntry
	cacheMu   sync.RWMutex
	cacheTTL  time.Duration
	lastFetch time.Time
}

// NewRemoteStore initializes a new RemoteStore.
// - remoteURL: The HTTP endpoint to fetch keys from.
// - cacheTTL: Duration to keep the cached keys before refreshing.
func NewRemoteStore(remoteURL string, apiKey string, cacheTTL time.Duration) *RemoteStore {
	return &RemoteStore{
		remoteURL: remoteURL,
		apiKey:    apiKey,
		client: &http.Client{
			Timeout: 10 * time.Second, // Adjust as needed
		},
		cacheTTL: cacheTTL,
	}
}

// SaveKey is not supported for RemoteStore as it's intended for fetching keys.
// If your remote service supports key creation, implement this method accordingly.
func (rs *RemoteStore) SaveKey(entry KeyEntry) error {
	return fmt.Errorf("SaveKey is not supported by RemoteStore")
}

// GetAllKeys retrieves all keys from the remote service or from the cache if valid.
func (rs *RemoteStore) GetAllKeys() ([]KeyEntry, error) {
	rs.cacheMu.RLock()
	if time.Since(rs.lastFetch) < rs.cacheTTL && rs.cache != nil {
		// Return cached keys
		keysCopy := make([]KeyEntry, len(rs.cache))
		copy(keysCopy, rs.cache)
		rs.cacheMu.RUnlock()
		return keysCopy, nil
	}
	rs.cacheMu.RUnlock()

	// Fetch keys from remote service
	// Create a new request to allow setting the Authorization header
	req, err := http.NewRequest("GET", rs.remoteURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %v", err)
	}
	// Set the API key as a Bearer token in the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rs.apiKey))

	resp, err := rs.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keys from remote service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote service returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var keyResponses []KeyResponse
	if err := json.Unmarshal(bodyBytes, &keyResponses); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	// Convert KeyResponse to KeyEntry
	var fetchedKeys []KeyEntry
	for _, kr := range keyResponses {
		keyBytes, err := base64.StdEncoding.DecodeString(kr.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key: %v", err)
		}

		infoBytes, err := base64.StdEncoding.DecodeString(kr.Info)
		if err != nil {
			return nil, fmt.Errorf("failed to decode info: %v", err)
		}

		fetchedKeys = append(fetchedKeys, KeyEntry{
			ID:     kr.ID,
			Key:    keyBytes,
			Info:   infoBytes,
			Expiry: kr.Expiry,
		})
	}

	// Update cache
	rs.cacheMu.Lock()
	rs.cache = fetchedKeys
	rs.lastFetch = time.Now()
	rs.cacheMu.Unlock()

	// Return a copy of the fetched keys
	keysCopy := make([]KeyEntry, len(fetchedKeys))
	copy(keysCopy, fetchedKeys)
	return keysCopy, nil
}
