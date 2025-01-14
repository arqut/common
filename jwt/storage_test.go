package jwt

import (
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// createTestKey is a helper function to generate a simple symmetric key for testing purposes.
func createTestKey(t *testing.T) jwk.Key {
	t.Helper()
	key, err := jwk.Import([]byte("dummy"))
	if err != nil {
		t.Fatalf("failed to create test key: %s", err)
	}
	return key
}

func TestInMemoryStorage_SaveAndGetActiveKey(t *testing.T) {
	store := NewInMemoryStorage()
	key := createTestKey(t)
	expiry := time.Now().Add(1 * time.Hour)

	if err := store.SaveActiveKey(key, expiry); err != nil {
		t.Fatalf("SaveActiveKey failed: %s", err)
	}

	gotKey, gotExpiry, err := store.GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey failed: %s", err)
	}

	// Use jwk.Equal to compare keys
	if !jwk.Equal(gotKey, key) {
		t.Errorf("retrieved key does not match saved key")
	}

	// Check expiry with some tolerance for slight timing differences
	if gotExpiry.Sub(expiry) > time.Second {
		t.Errorf("expected expiry %v, got %v", expiry, gotExpiry)
	}
}

func TestInMemoryStorage_SaveAndGetPreviousKeys(t *testing.T) {
	store := NewInMemoryStorage()
	expiry := time.Now().Add(2 * time.Hour)

	// Save multiple previous keys
	for i := 0; i < 3; i++ {
		key := createTestKey(t)
		if err := store.SavePreviousKey(key, expiry); err != nil {
			t.Fatalf("SavePreviousKey failed at iteration %d: %s", i, err)
		}
	}

	prevKeys, err := store.GetPreviousKeys()
	if err != nil {
		t.Fatalf("GetPreviousKeys failed: %s", err)
	}

	if len(prevKeys) != 3 {
		t.Errorf("expected 3 previous keys, got %d", len(prevKeys))
	}

	// Verify that the stored keys match by checking equality
	for _, kw := range prevKeys {
		if kw.Expiry.Sub(expiry) > time.Second {
			t.Errorf("expected expiry %v, got %v", expiry, kw.Expiry)
		}
	}
}

func TestInMemoryStorage_SetPreviousKeys(t *testing.T) {
	store := NewInMemoryStorage()
	expiry := time.Now().Add(3 * time.Hour)

	// Initialize with some previous keys
	initialKeys := []KeyWithExpiry{}
	for i := 0; i < 2; i++ {
		key := createTestKey(t)
		initialKeys = append(initialKeys, KeyWithExpiry{Key: key, Expiry: expiry})
	}
	if err := store.SetPreviousKeys(initialKeys); err != nil {
		t.Fatalf("SetPreviousKeys failed: %s", err)
	}

	// Verify the keys were set correctly
	prevKeys, err := store.GetPreviousKeys()
	if err != nil {
		t.Fatalf("GetPreviousKeys failed: %s", err)
	}
	if len(prevKeys) != len(initialKeys) {
		t.Errorf("expected %d previous keys, got %d", len(initialKeys), len(prevKeys))
	}

	// Update previous keys with a new slice
	newKeys := []KeyWithExpiry{}
	for i := 0; i < 5; i++ {
		key := createTestKey(t)
		newKeys = append(newKeys, KeyWithExpiry{Key: key, Expiry: expiry})
	}
	if err := store.SetPreviousKeys(newKeys); err != nil {
		t.Fatalf("SetPreviousKeys (update) failed: %s", err)
	}

	prevKeys, err = store.GetPreviousKeys()
	if err != nil {
		t.Fatalf("GetPreviousKeys failed: %s", err)
	}
	if len(prevKeys) != len(newKeys) {
		t.Errorf("after update, expected %d previous keys, got %d", len(newKeys), len(prevKeys))
	}
}

func TestInMemoryStorage_Concurrency(t *testing.T) {
	store := NewInMemoryStorage()
	expiry := time.Now().Add(1 * time.Hour)

	var wg sync.WaitGroup
	concurrency := 10

	// Run concurrent writes to SavePreviousKey and SaveActiveKey.
	for i := 0; i < concurrency; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			key := createTestKey(t)
			if err := store.SaveActiveKey(key, expiry); err != nil {
				t.Errorf("concurrent SaveActiveKey failed: %s", err)
			}
		}()

		go func() {
			defer wg.Done()
			key := createTestKey(t)
			if err := store.SavePreviousKey(key, expiry); err != nil {
				t.Errorf("concurrent SavePreviousKey failed: %s", err)
			}
		}()
	}

	wg.Wait()

	// After concurrent operations, ensure that GetActiveKey and GetPreviousKeys don't error out.
	if _, _, err := store.GetActiveKey(); err != nil {
		t.Errorf("GetActiveKey after concurrency failed: %s", err)
	}
	if _, err := store.GetPreviousKeys(); err != nil {
		t.Errorf("GetPreviousKeys after concurrency failed: %s", err)
	}
}
