package jwt

import (
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestInMemoryKeyStore(t *testing.T) {
	store := NewInMemoryKeyStore()

	key1 := KeyEntry{Key: []byte("key1"), Info: []byte("info1"), Expiry: time.Now().Add(time.Hour)}
	if err := store.SaveKey(key1); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	keys, err := store.GetAllKeys()
	if err != nil {
		t.Fatalf("Failed to get all keys: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(keys))
	}

	if string(keys[0].Key) != "key1" {
		t.Errorf("Expected key 'key1', got %s", keys[0].Key)
	}
}

func TestGormKeyStore(t *testing.T) {
	// Initialize an in-memory SQLite DB for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open in-memory SQLite DB: %v", err)
	}

	store := NewGormKeyStore(db)

	key1 := KeyEntry{Key: []byte("gormkey"), Info: []byte("gorminfo"), Expiry: time.Now().Add(time.Hour)}
	if err := store.SaveKey(key1); err != nil {
		t.Fatalf("Failed to save key using GORM: %v", err)
	}

	keys, err := store.GetAllKeys()
	if err != nil {
		t.Fatalf("Failed to retrieve keys using GORM: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("Expected 1 key from GORM store, got %d", len(keys))
	}

	if string(keys[0].Key) != "gormkey" {
		t.Errorf("Expected key 'gormkey', got %s", keys[0].Key)
	}
}
