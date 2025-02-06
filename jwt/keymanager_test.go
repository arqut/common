// keymanager_test.go
package jwt

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/arqut/common/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain sets up the environment before running tests.
func TestMain(m *testing.M) {
	// Initialize logger with a simple logger.
	// Adjust the configuration as needed.
	os.Setenv("SYS_LOG_LEVEL", "INFO")
	system.InitLogger("test_logger")

	// Run the tests.
	code := m.Run()

	// Exit with the appropriate code.
	os.Exit(code)
}

func TestKeyManager_IssueAndDecryptJWE(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 1 * time.Hour
	km, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create KeyManager")

	payload := []byte("test payload")
	jweOptions := &JWEOptions{
		ExpiresIn: 30 * time.Minute,
		Headers: map[string]interface{}{
			"custom-header": "custom-value",
		},
	}

	// Issue JWE
	token, err := km.IssueJWE(payload, jweOptions)
	assert.NoError(t, err, "IssueJWE should not return an error")
	assert.NotEmpty(t, token, "Issued JWE should not be empty")

	// Decrypt JWE
	decrypted, err := km.DecryptJWE(token)
	assert.NoError(t, err, "DecryptJWE should not return an error")
	assert.Equal(t, payload, decrypted, "Decrypted payload should match original payload")
}

func TestKeyManager_KeyRotation(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 2 * time.Second
	km, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create KeyManager")

	initialKey := km.currentKey
	require.NotNil(t, initialKey.Key, "Initial key should not be nil")

	// Wait for rotation to occur
	time.Sleep(3 * time.Second)

	// Fetch all keys from the store
	keys, err := store.GetAllKeys()
	require.NoError(t, err, "GetAllKeys should not return an error")
	require.Len(t, keys, 2, "There should be two keys after rotation")

	newKey := km.currentKey
	assert.NotEqual(t, initialKey.Key, newKey.Key, "New key should be different from the initial key")
	assert.Equal(t, initialKey, keys[0], "Initial key should be in the key history")
	assert.Equal(t, newKey, keys[1], "New key should be the current key")
}

func TestKeyManager_ValidationOnlyMode(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 1 * time.Hour
	// Initialize with a key
	kmIssuer, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create Issuer KeyManager")

	payload := []byte("validation payload")
	token, err := kmIssuer.IssueJWE(payload, nil)
	assert.NoError(t, err, "IssueJWE should not return an error")

	// Create a validation-only KeyManager
	kmValidator, err := NewValidationKeyManager(store)
	require.NoError(t, err, "Failed to create Validation KeyManager")

	// Attempt to issue JWE in validation-only mode
	_, err = kmValidator.IssueJWE(payload, nil)
	assert.Error(t, err, "IssueJWE should return an error in validation-only mode")

	// Attempt to decrypt JWE in validation-only mode
	decrypted, err := kmValidator.DecryptJWE(token)
	assert.NoError(t, err, "DecryptJWE should not return an error in validation-only mode")
	assert.Equal(t, payload, decrypted, "Decrypted payload should match original payload")
}

func TestKeyManager_JWEExpiration(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 1 * time.Hour
	km, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create KeyManager")

	payload := []byte("payload with expiration")
	jweOptions := &JWEOptions{
		ExpiresIn: 1 * time.Second,
	}

	// Issue JWE
	token, err := km.IssueJWE(payload, jweOptions)
	assert.NoError(t, err, "IssueJWE should not return an error")

	// Wait for the token to expire
	time.Sleep(2 * time.Second)

	// Attempt to decrypt expired JWE
	decrypted, err := km.DecryptJWE(token)
	assert.Error(t, err, "DecryptJWE should return an error for expired token")
	assert.Nil(t, decrypted, "Decrypted payload should be nil for expired token")
}

func TestKeyManager_DecryptionWithOldKey(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 1 * time.Second
	km, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create KeyManager")

	payload := []byte("payload for old key")

	// Issue JWE with the initial key
	token1, err := km.IssueJWE(payload, nil)
	require.NoError(t, err, "IssueJWE should not return an error")

	// Wait for rotation to occur
	time.Sleep(2 * time.Second)

	// Issue JWE with the new key
	token2, err := km.IssueJWE(payload, nil)
	require.NoError(t, err, "IssueJWE should not return an error")

	// Both tokens should be decryptable
	decrypted1, err := km.DecryptJWE(token1)
	assert.NoError(t, err, "DecryptJWE for token1 should not return an error")
	assert.Equal(t, payload, decrypted1, "Decrypted payload1 should match original payload")

	decrypted2, err := km.DecryptJWE(token2)
	assert.NoError(t, err, "DecryptJWE for token2 should not return an error")
	assert.Equal(t, payload, decrypted2, "Decrypted payload2 should match original payload")
}

func TestKeyManager_Shutdown(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 1 * time.Second
	km, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create KeyManager")

	// Shutdown the KeyManager
	km.Shutdown()

	// Wait to ensure the rotation goroutine has stopped
	time.Sleep(2 * time.Second)

	// Check that no new keys are added after shutdown
	initialKey := km.currentKey
	time.Sleep(2 * time.Second)
	keys, err := store.GetAllKeys()
	require.NoError(t, err, "GetAllKeys should not return an error")
	require.Len(t, keys, 1, "There should still be only one key after shutdown")
	assert.Equal(t, initialKey, km.currentKey, "Current key should remain unchanged after shutdown")
}

func TestKeyManager_DecryptJWE_WithInvalidKey(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 1 * time.Hour
	km, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create KeyManager")

	payload := []byte("test payload")
	token, err := km.IssueJWE(payload, nil)
	require.NoError(t, err, "IssueJWE should not return an error")

	// Corrupt the token by modifying a byte
	corruptedToken := make([]byte, len(token))
	copy(corruptedToken, token)
	corruptedToken[len(corruptedToken)-1] ^= 0xFF // Flip the last byte

	// Attempt to decrypt the corrupted token
	decrypted, err := km.DecryptJWE(corruptedToken)
	assert.Error(t, err, "DecryptJWE should return an error for corrupted token")
	assert.Nil(t, decrypted, "Decrypted payload should be nil for corrupted token")
}

func TestKeyManager_IssueJWE_InValidationOnlyMode(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 1 * time.Hour
	kmIssuer, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create Issuer KeyManager")

	payload := []byte("test payload")

	// Issue a JWE to populate the store
	_, err = kmIssuer.IssueJWE(payload, nil)
	require.NoError(t, err, "IssueJWE should not return an error")

	// Create a validation-only KeyManager
	kmValidator, err := NewValidationKeyManager(store)
	require.NoError(t, err, "Failed to create Validation KeyManager")

	// Attempt to issue JWE in validation-only mode
	_, err = kmValidator.IssueJWE(payload, nil)
	assert.Error(t, err, "IssueJWE should return an error in validation-only mode")
}

func TestKeyManager_DeriveKey(t *testing.T) {
	masterKey := []byte("master_key_example")
	salt, err := generateSalt()
	require.NoError(t, err, "generateSalt should not return an error")

	info := []byte("test_info")
	derivedKey, err := deriveKey(masterKey, salt, info)
	require.NoError(t, err, "deriveKey should not return an error")
	assert.Len(t, derivedKey, 32, "Derived key should be 32 bytes long")
}

func TestKeyManager_JWE_WithCustomHeaders(t *testing.T) {
	store := NewInMemoryKeyStore()

	rotationPeriod := 1 * time.Hour
	km, err := NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to create KeyManager")

	payload := []byte("payload with custom headers")
	jweOptions := &JWEOptions{
		ExpiresIn: 30 * time.Minute,
		Headers: map[string]interface{}{
			"custom-header1": "value1",
			"custom-header2": 12345,
		},
	}

	token, err := km.IssueJWE(payload, jweOptions)
	require.NoError(t, err, "IssueJWE should not return an error")
	assert.NotEmpty(t, token, "Issued JWE should not be empty")

	// Parse the JWE to verify headers
	decrypted, err := km.DecryptJWE(token)
	assert.NoError(t, err, "DecryptJWE should not return an error")
	assert.Equal(t, payload, decrypted, "Decrypted payload should match original payload")
}

func TestKeyManager_RotateKey_InValidationOnlyMode(t *testing.T) {
	store := NewInMemoryKeyStore()

	// Add a key to the store
	initialKey := KeyEntry{
		Key:    []byte("initial_key"),
		Info:   []byte("initial_info"),
		Expiry: time.Now().Add(24 * time.Hour),
	}
	err := store.SaveKey(initialKey)
	require.NoError(t, err, "Failed to save initial key to store")

	// Create a validation-only KeyManager
	kmValidator, err := NewValidationKeyManager(store)
	require.NoError(t, err, "Failed to create Validation KeyManager")

	// Attempt to rotate key in validation-only mode
	err = kmValidator.rotateKey()
	assert.Error(t, err, "rotateKey should return an error in validation-only mode")
}

func TestGetCurrentKeys_WithMoreThanFourHistoryKeys(t *testing.T) {
	// Step 1: Initialize an in-memory key store
	store := NewInMemoryKeyStore()

	// Step 2: Insert 6 keys (1 current + 5 historical)
	totalKeys := 6
	now := time.Now()

	for i := 0; i < totalKeys; i++ {
		key := KeyEntry{
			Key:    []byte{byte(i + 1)},                   // Simple incremental keys
			Info:   []byte("info" + strconv.Itoa(i+1)),    // Simple info strings
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
	// - Current Key: Key5 (last inserted)
	// - Two most recent historical keys: Key3 and Key4
	expectedKeys := []KeyEntry{
		{
			Key:    []byte{6}, // Key5
			Info:   []byte("info6"),
			Expiry: now.Add(5 * time.Hour),
		},
		{
			Key:    []byte{4}, // Key3
			Info:   []byte("info4"),
			Expiry: now.Add(3 * time.Hour),
		},
		{
			Key:    []byte{5}, // Key4
			Info:   []byte("info5"),
			Expiry: now.Add(4 * time.Hour),
		},
	}

	// Assert that the returned keys match the expected keys
	for i, key := range keys {
		expectedKey := expectedKeys[i]

		if string(key.Key) != string(expectedKey.Key) {
			t.Errorf("Key %d: expected Key %v, got %v", i, expectedKey.Key, key.Key)
		}
		if string(key.Info) != string(expectedKey.Info) {
			t.Errorf("Key %d: expected Info %v, got %v", i, expectedKey.Info, key.Info)
		}
		if !key.Expiry.Equal(expectedKey.Expiry) {
			t.Errorf("Key %d: expected Expiry %v, got %v", i, expectedKey.Expiry, key.Expiry)
		}
	}
}
