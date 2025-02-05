package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"
)

func TestInMemoryKeyStore(t *testing.T) {
	store := NewInMemoryKeyStore()

	// Test SaveKey
	key1 := KeyEntry{
		Key:    []byte("key1"),
		Info:   []byte("info1"),
		Expiry: time.Now().Add(24 * time.Hour),
	}
	err := store.SaveKey(key1)
	assert.NoError(t, err, "SaveKey should not return an error")

	// Test GetAllKeys
	keys, err := store.GetAllKeys()
	assert.NoError(t, err, "GetAllKeys should not return an error")
	assert.Len(t, keys, 1, "There should be one key in the store")
	assert.Equal(t, key1, keys[0], "Retrieved key should match the saved key")

	// Test saving multiple keys and ordering
	key2 := KeyEntry{
		Key:    []byte("key2"),
		Info:   []byte("info2"),
		Expiry: time.Now().Add(48 * time.Hour),
	}
	key3 := KeyEntry{
		Key:    []byte("key3"),
		Info:   []byte("info3"),
		Expiry: time.Now().Add(12 * time.Hour),
	}
	store.SaveKey(key2)
	store.SaveKey(key3)

	keys, err = store.GetAllKeys()
	assert.NoError(t, err, "GetAllKeys should not return an error")
	assert.Len(t, keys, 3, "There should be three keys in the store")

	// Keys should be sorted by Expiry ascending
	assert.Equal(t, key3, keys[0], "Key with earliest expiry should be first")
	assert.Equal(t, key1, keys[1], "Key with middle expiry should be second")
	assert.Equal(t, key2, keys[2], "Key with latest expiry should be third")
}

func TestGormKeyStore(t *testing.T) {
	// Use in-memory SQLite for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err, "Should connect to in-memory SQLite without error")

	store := NewGormKeyStore(db)

	// Ensure the KeyEntry table is created
	exists := db.Migrator().HasTable(&KeyEntry{})
	assert.True(t, exists, "KeyEntry table should exist after migration")

	// Test SaveKey
	key1 := KeyEntry{
		Key:    []byte("gorm_key1"),
		Info:   []byte("gorm_info1"),
		Expiry: time.Now().Add(24 * time.Hour),
	}
	err = store.SaveKey(key1)
	assert.NoError(t, err, "SaveKey should not return an error")

	// Test GetAllKeys
	keys, err := store.GetAllKeys()
	assert.NoError(t, err, "GetAllKeys should not return an error")
	assert.Len(t, keys, 1, "There should be one key in the store")
	assert.Equal(t, key1.Key, keys[0].Key, "Retrieved key should match the saved key")
	assert.Equal(t, key1.Info, keys[0].Info, "Retrieved info should match the saved info")
	assert.WithinDuration(t, key1.Expiry, keys[0].Expiry, time.Second, "Expiry should match")

	// Test saving multiple keys and ordering
	key2 := KeyEntry{
		Key:    []byte("gorm_key2"),
		Info:   []byte("gorm_info2"),
		Expiry: time.Now().Add(48 * time.Hour),
	}
	key3 := KeyEntry{
		Key:    []byte("gorm_key3"),
		Info:   []byte("gorm_info3"),
		Expiry: time.Now().Add(12 * time.Hour),
	}
	store.SaveKey(key2)
	store.SaveKey(key3)

	keys, err = store.GetAllKeys()
	assert.NoError(t, err, "GetAllKeys should not return an error")
	assert.Len(t, keys, 3, "There should be three keys in the store")

	// Keys should be sorted by Expiry ascending
	assert.Equal(t, key3.Key, keys[0].Key, "Key with earliest expiry should be first")
	assert.Equal(t, key1.Key, keys[1].Key, "Key with middle expiry should be second")
	assert.Equal(t, key2.Key, keys[2].Key, "Key with latest expiry should be third")
}

func MockRemoteService(t *testing.T, keys []KeyResponse, statusCode int) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			json.NewEncoder(w).Encode(keys)
		} else {
			fmt.Fprintf(w, "Error: status code %d", statusCode)
		}
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func TestRemoteStore_GetAllKeys_CacheBehavior(t *testing.T) {
	// Step 1: Initialize an in-memory key store
	store := NewInMemoryKeyStore()

	// Step 2: Insert 6 keys (1 current + 5 historical)
	totalKeys := 6
	now := time.Now()

	for i := 0; i < totalKeys; i++ {
		key := KeyEntry{
			Key:    []byte{byte(i + 1)},                   // Simple incremental keys
			Info:   []byte("info" + strconv.Itoa(i+1)),    // Corrected info strings
			Expiry: now.Add(time.Duration(i) * time.Hour), // Increasing expiry times
		}
		if err := store.SaveKey(key); err != nil {
			t.Fatalf("Failed to save key %d: %v", i, err)
		}
	}

	// Step 3: Initialize KeyManager with a long rotation period to prevent auto-rotation during test
	rotationPeriod := 24 * time.Hour
	km, err := NewIssuerKeyManager(rotationPeriod, store)
	if err != nil {
		t.Fatalf("Failed to initialize KeyManager: %v", err)
	}
	defer km.Shutdown()

	// Step 4: Invoke GetCurrentKeys
	keys, err := km.GetCurrentKeys()
	if err != nil {
		t.Fatalf("GetCurrentKeys failed: %v", err)
	}

	// Step 5: Assert that exactly 3 keys are returned
	expectedCount := 3
	if len(keys) != expectedCount {
		t.Errorf("Expected %d keys, got %d", expectedCount, len(keys))
	}

	// Define the expected keys:
	// - Current Key: Key6 (last inserted)
	// - Two most recent historical keys: Key5 and Key4
	expectedKeys := []KeyEntry{
		{
			Key:    []byte{6}, // Key6
			Info:   []byte("info6"),
			Expiry: now.Add(5 * time.Hour),
		},
		{
			Key:    []byte{5}, // Key5
			Info:   []byte("info5"),
			Expiry: now.Add(4 * time.Hour),
		},
		{
			Key:    []byte{4}, // Key4
			Info:   []byte("info4"),
			Expiry: now.Add(3 * time.Hour),
		},
	}

	// Assert that the returned keys match the expected keys
	for i, key := range keys {
		expectedKey := expectedKeys[i]

		// Compare ID
		if key.ID != expectedKey.ID {
			t.Errorf("Key %d: expected ID %d, got %d", i, expectedKey.ID, key.ID)
		}

		// Compare Key
		if string(key.Key) != string(expectedKey.Key) {
			t.Errorf("Key %d: expected Key %v, got %v", i, expectedKey.Key, key.Key)
		}

		// Compare Info
		if string(key.Info) != string(expectedKey.Info) {
			t.Errorf("Key %d: expected Info %v, got %v", i, expectedKey.Info, key.Info)
		}

		// Compare Expiry using time.Equal to ignore monotonic clock readings
		if !key.Expiry.Equal(expectedKey.Expiry) {
			t.Errorf("Key %d: expected Expiry %v, got %v", i, expectedKey.Expiry, key.Expiry)
		}
	}
}

// func TestRemoteStore_GetAllKeys_ErrorHandling(t *testing.T) {
//     // Create a mock server that returns an error
//     server := MockRemoteService(t, nil, http.StatusInternalServerError)

//     // Initialize RemoteStore
//     cacheTTL := 10 * time.Minute
//     remoteStore := NewRemoteStore(server.URL, cacheTTL)

//     // Attempt to fetch keys: should return an error
//     _, err := remoteStore.GetAllKeys()
//     if err == nil {
//         t.Fatalf("Expected error when fetching keys from server with error, but got none")
//     }

//     expectedErrMsg := "remote service returned status 500: Error: status code 500"
//     if err.Error() != expectedErrMsg {
//         t.Errorf("Expected error message '%s', got '%s'", expectedErrMsg, err.Error())
//     }
// }

// func TestRemoteStore_SaveKey(t *testing.T) {
//     // Initialize RemoteStore
//     server := MockRemoteService(t, nil, http.StatusOK)
//     cacheTTL := 10 * time.Minute
//     remoteStore := NewRemoteStore(server.URL, cacheTTL)

//     // Attempt to save a key: should return an error
//     err := remoteStore.SaveKey(KeyEntry{})
//     if err == nil {
//         t.Fatalf("Expected error when calling SaveKey on RemoteStore, but got none")
//     }

//     expectedErrMsg := "SaveKey is not supported by RemoteStore"
//     if err.Error() != expectedErrMsg {
//         t.Errorf("Expected error message '%s', got '%s'", expectedErrMsg, err.Error())
//     }
// }

// func TestRemoteStore_ConcurrentAccess(t *testing.T) {
//     // Define mock keys
//     keys := []KeyResponse{
//         {
//             ID:     1,
//             Key:    base64.StdEncoding.EncodeToString([]byte{1}),
//             Info:   base64.StdEncoding.EncodeToString([]byte("info1")),
//             Expiry: time.Now().Add(1 * time.Hour),
//         },
//     }

//     // Create a mock server that returns the mock keys
//     server := MockRemoteService(t, keys, http.StatusOK)

//     // Initialize RemoteStore with a cache TTL
//     cacheTTL := 10 * time.Minute
//     remoteStore := NewRemoteStore(server.URL, cacheTTL)

//     // Define a wait group for concurrency
//     var wg sync.WaitGroup
//     concurrency := 10

//     // Function to fetch keys
//     fetchFunc := func() {
//         defer wg.Done()
//         fetchedKeys, err := remoteStore.GetAllKeys()
//         if err != nil {
//             t.Errorf("GetAllKeys failed: %v", err)
//             return
//         }

//         expectedKeys := []KeyEntry{
//             {
//                 ID:     1,
//                 Key:    []byte{1},
//                 Info:   []byte("info1"),
//                 Expiry: keys[0].Expiry,
//             },
//         }

//         if !reflect.DeepEqual(fetchedKeys, expectedKeys) {
//             t.Errorf("Fetched keys do not match expected keys.\nExpected: %+v\nGot: %+v", expectedKeys, fetchedKeys)
//         }
//     }

//     // Launch multiple goroutines to fetch keys concurrently
//     for i := 0; i < concurrency; i++ {
//         wg.Add(1)
//         go fetchFunc()
//     }

//     // Wait for all goroutines to finish
//     wg.Wait()
// }
