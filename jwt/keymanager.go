package jwt

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"golang.org/x/crypto/hkdf"

	"github.com/arqut/common/system"
)

type JWEOptions struct {
	ExpiresIn time.Duration
	Headers   map[string]interface{}
}

type KeyManager struct {
	currentKey     KeyEntry
	keyHistory     []KeyEntry
	rotationPeriod time.Duration
	mu             sync.RWMutex
	store          KeyStore
	validationOnly bool
	ctx            context.Context
	cancel         context.CancelFunc
}

type KeyResponse struct {
	ID     uint      `json:"id,omitempty"` // Omit if not using GormKeyStore
	Key    string    `json:"key"`          // Base64 encoded key
	Info   string    `json:"info"`         // Base64 encoded info
	Expiry time.Time `json:"expiry"`       // Expiration time
}

func WithKeyManager(keyManager *KeyManager, handler func(*fiber.Ctx, *KeyManager) error) func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		return handler(c, keyManager)
	}
}

// NewIssuerKeyManager creates a new KeyManager in issuer & validation mode.
func NewIssuerKeyManager(rotationPeriod time.Duration, store KeyStore) (*KeyManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	km := &KeyManager{
		rotationPeriod: rotationPeriod,
		store:          store,
		validationOnly: false,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Fetch all existing keys from the store
	keys, err := store.GetAllKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve keys from store: %v", err)
	}

	if len(keys) > 0 {
		// Set the most recent key as the current key
		km.currentKey = keys[len(keys)-1]
		if len(keys) > 1 {
			km.keyHistory = keys[:len(keys)-1]
		}

		if len(keys) > 1 {
			// Determine the start index to keep only the last three keys
			start := 0
			if len(keys)-1 > 2 {
				start = len(keys) - 1 - 2
			}
			km.keyHistory = keys[start : len(keys)-1]
		} else {
			km.keyHistory = keys
		}

		// Check if the current key is nearing expiration
		timeUntilExpiry := time.Until(km.currentKey.Expiry)
		// Define a threshold for rotation, e.g., rotate 10% before expiry
		rotationThreshold := time.Duration(float64(km.rotationPeriod) * 0.1)
		system.Logger.Info("Check if rotating key is required...")
		if timeUntilExpiry <= rotationThreshold {
			system.Logger.Info("Current key is nearing expiration. Rotating key...")
			if err := km.rotateKey(); err != nil {
				return nil, fmt.Errorf("failed to rotate key: %v", err)
			}
		}
	} else {
		// No existing keys found; generate an initial key
		system.Logger.Info("No existing keys found. Generating initial key...")
		if err := km.rotateKey(); err != nil {
			return nil, fmt.Errorf("failed to initialize key manager: %v", err)
		}
	}

	go km.startKeyRotation()

	return km, nil
}

// NewValidationKeyManager creates a new KeyManager in validation only mode,
// retrieving keys from the provided store.
func NewValidationKeyManager(store KeyStore) (*KeyManager, error) {
	km := &KeyManager{
		store:          store,
		validationOnly: true,
	}

	err := km.RefreshKeys()
	if err != nil {
		return nil, err
	}

	return km, nil
}

func (km *KeyManager) RefreshKeys() error {
	keys, err := km.store.GetAllKeys()
	if err != nil {
		return fmt.Errorf("failed to retrieve keys from store: %v", err)
	}

	if len(keys) == 0 {
		return fmt.Errorf("no keys available in store for validation")
	}

	km.currentKey = keys[0]
	if len(keys) > 1 {
		km.keyHistory = keys[1:]
	}

	return nil
}

func (km *KeyManager) rotateKey() error {
	if km.validationOnly {
		return fmt.Errorf("rotateKey not allowed in validation only mode")
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return fmt.Errorf("failed to generate new key: %v", err)
	}

	newInfo := []byte(fmt.Sprintf("encryption-key-%d", time.Now().Unix()))
	newExpiry := time.Now().Add(km.rotationPeriod)

	if km.currentKey.Key != nil {
		km.keyHistory = append(km.keyHistory, km.currentKey)
		if len(km.keyHistory) > 3 {
			km.keyHistory = km.keyHistory[1:len(km.keyHistory)]
		}
	}

	km.currentKey = KeyEntry{
		Key:    newKey,
		Info:   newInfo,
		Expiry: newExpiry,
	}

	if err := km.store.SaveKey(km.currentKey); err != nil {
		return fmt.Errorf("failed to save key: %v", err)
	}

	return nil
}

func (km *KeyManager) startKeyRotation() {
	ticker := time.NewTicker(km.rotationPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := km.rotateKey(); err != nil {
				system.Logger.Errorf("Error rotating key: %v", err)
			} else {
				system.Logger.Infof("Key rotated successfully.")
			}
		case <-km.ctx.Done():
			system.Logger.Infof("Key rotation goroutine shutting down.")
			return
		}
	}
}

func (km *KeyManager) GetCurrentKeys() ([]KeyEntry, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var currentKeys []KeyEntry

	// Start with the current key
	currentKeys = append(currentKeys, km.currentKey)

	// Determine how many historical keys to include
	historyCount := 2 // since we already have the current key
	if len(km.keyHistory) < historyCount {
		historyCount = len(km.keyHistory)
	}

	// Append the required number of historical keys
	if historyCount > 0 {
		currentKeys = append(currentKeys, km.keyHistory[len(km.keyHistory)-historyCount:]...)
	}

	return currentKeys, nil
}

func (km *KeyManager) GetCurrentKeysAPIHandler(c *fiber.Ctx) error {
	keys, err := km.GetCurrentKeys()
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Access denied",
		})
	}

	var response []KeyResponse
	for _, key := range keys {
		kr := KeyResponse{
			Expiry: key.Expiry,
			Key:    base64.StdEncoding.EncodeToString(key.Key),
			Info:   base64.StdEncoding.EncodeToString(key.Info),
		}

		// Include ID only if it's set (useful for GormKeyStore)
		if key.ID != 0 {
			kr.ID = key.ID
		}

		response = append(response, kr)
	}

	return c.JSON(response)
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

func deriveKey(masterKey, salt, info []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, masterKey, salt, info)
	derivedKey := make([]byte, 32)
	if _, err := hkdf.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}
	return derivedKey, nil
}

func (km *KeyManager) Shutdown() {
	km.cancel()
}

func (km *KeyManager) IssueJWE(payload []byte, opts *JWEOptions) ([]byte, error) {
	if km.validationOnly {
		return nil, fmt.Errorf("IssueJWE not allowed in validation only mode")
	}

	km.mu.RLock()
	if time.Now().After(km.currentKey.Expiry) {
		km.mu.RUnlock()
		if err := km.rotateKey(); err != nil {
			return nil, fmt.Errorf("failed to rotate key: %v", err)
		}
		km.mu.RLock()
	}
	defer km.mu.RUnlock()

	salt, err := generateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	derivedKey, err := deriveKey(km.currentKey.Key, salt, km.currentKey.Info)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	headers := jwe.NewHeaders()
	headers.Set("salt", base64.StdEncoding.EncodeToString(salt))
	headers.Set("kid", base64.StdEncoding.EncodeToString(km.currentKey.Info))
	headers.Set("iat", time.Now().Unix())

	if opts != nil {
		if opts.ExpiresIn > 0 {
			headers.Set("exp", time.Now().Add(opts.ExpiresIn).Unix())
		}
		for k, v := range opts.Headers {
			headers.Set(k, v)
		}
	}

	encrypted, err := jwe.Encrypt(
		payload,
		jwe.WithKey(jwa.DIRECT(), derivedKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
		jwe.WithProtectedHeaders(headers),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt JWE: %v", err)
	}

	return encrypted, nil
}

func (km *KeyManager) DecryptJWE(token []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	msg, err := jwe.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWE: %v", err)
	}

	headers := msg.ProtectedHeaders()
	var expiration float64
	if err := headers.Get("exp", &expiration); err == nil {
		expTime := time.Unix(int64(expiration), 0)
		if time.Now().After(expTime) {
			return nil, fmt.Errorf("token has expired")
		}
	}

	var saltStr string
	if err := headers.Get("salt", &saltStr); err != nil {
		return nil, fmt.Errorf("failed to get salt from headers: %v", err)
	}

	saltBytes, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %v", err)
	}

	allKeys := append([]KeyEntry{km.currentKey}, km.keyHistory...)

	for _, keyEntry := range allKeys {
		derivedKey, err := deriveKey(keyEntry.Key, saltBytes, keyEntry.Info)
		if err != nil {
			continue
		}
		decrypted, err := jwe.Decrypt(token, jwe.WithKey(jwa.DIRECT(), derivedKey))
		if err == nil {
			return decrypted, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt JWE with any known key")
}
