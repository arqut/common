package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"golang.org/x/crypto/hkdf"
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
}

// NewIssuerKeyManager creates a new KeyManager in issuer & validation mode.
func NewIssuerKeyManager(rotationPeriod time.Duration, store KeyStore) (*KeyManager, error) {
	km := &KeyManager{
		rotationPeriod: rotationPeriod,
		store:          store,
		validationOnly: false,
	}
	if err := km.rotateKey(); err != nil {
		return nil, fmt.Errorf("failed to initialize key manager: %v", err)
	}
	return km, nil
}

// NewValidationKeyManager creates a new KeyManager in validation only mode,
// retrieving keys from the provided store.
func NewValidationKeyManager(store KeyStore) (*KeyManager, error) {
	km := &KeyManager{
		store:          store,
		validationOnly: true,
	}

	keys, err := store.GetAllKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve keys from store: %v", err)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys available in store for validation")
	}

	km.currentKey = keys[0]
	if len(keys) > 1 {
		km.keyHistory = keys[1:]
	}

	return km, nil
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
