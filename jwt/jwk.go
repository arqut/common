package jwt

import (
	"fmt"
	"log"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/arqut/common/utils"
)

type KeyManager struct {
	storage           JWKStorage
	keyRotationPeriod time.Duration // or you could store an expiry date per key
	maxPreviousKeys   int
}

func NewKeyManager(storage JWKStorage, rotationPeriod time.Duration, maxPrevious int) *KeyManager {
	return &KeyManager{
		storage:           storage,
		keyRotationPeriod: rotationPeriod,
		maxPreviousKeys:   maxPrevious,
	}
}

func (km *KeyManager) InitKeysIfNeeded() error {
	activeKey, _, err := km.storage.GetActiveKey()
	if err != nil || activeKey == nil {
		// No active key found; generate a new one
		log.Println("[KeyManager] No active key. Generating new key pair...")
		return km.RotateKey()
	}
	return nil
}

func (km *KeyManager) RotateKey() error {
	// Create new EC key
	newKey, err := km.generateECKey()
	if err != nil {
		return fmt.Errorf("failed to generate new EC key: %w", err)
	}
	// Prepare expiry for the new key (use your own logic, e.g., add rotationPeriod)
	newExpiry := time.Now().Add(km.keyRotationPeriod)

	// Move old active key to previous (if exists)
	oldKey, oldKeyExpiry, err := km.storage.GetActiveKey()
	if err == nil && oldKey != nil {
		if err := km.storage.SavePreviousKey(oldKey, oldKeyExpiry); err != nil {
			return fmt.Errorf("failed to save previous key: %w", err)
		}
	}

	// Set new key as active
	if err := km.storage.SaveActiveKey(newKey, newExpiry); err != nil {
		return fmt.Errorf("failed to save new active key: %w", err)
	}

	// Prune older keys beyond maxPreviousKeys
	if err := km.pruneOldKeys(); err != nil {
		return fmt.Errorf("failed to prune old keys: %w", err)
	}

	return nil
}

func (km *KeyManager) pruneOldKeys() error {
	keys, err := km.storage.GetPreviousKeys()
	if err != nil {
		return err
	}
	if len(keys) <= km.maxPreviousKeys {
		return nil
	}
	// keep the last 'maxPreviousKeys' keys
	start := len(keys) - km.maxPreviousKeys
	pruned := keys[start:]
	return km.storage.SetPreviousKeys(pruned)
}

func (km *KeyManager) generateECKey() (jwk.Key, error) {
	// Generate a native ECDSA private key (P-256 in this example)
	rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ecdsa key: %w", err)
	}

	// Convert to JWK

	key, err := jwk.Import(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from ecdsa key: %w", err)
	}

	keysID, err := utils.GenerateRandomString(10)
	if err != nil {
		return nil, err
	}

	// Set a key ID, algorithm, etc. as needed
	if err := key.Set(jwk.KeyIDKey, keysID); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.ECDH_ES_A256KW()); err != nil {
		return nil, err
	}

	// (Optional) You can set additional parameters here, e.g., key usage or more.
	return key, nil
}

func (km *KeyManager) MustRotateNow() (bool, error) {
	_, expiry, err := km.storage.GetActiveKey()
	if err != nil {
		return false, err
	}
	return time.Now().After(expiry), nil
}

func (km *KeyManager) GetPublicJWKSet() (jwk.Set, error) {
	set := jwk.NewSet()

	// Active key
	activeKey, _, err := km.storage.GetActiveKey()
	if err == nil && activeKey != nil {
		pubKey, err := activeKey.PublicKey()
		if err == nil {
			set.AddKey(pubKey)
		}
	}

	// Previous keys
	prevKeys, err := km.storage.GetPreviousKeys()
	if err == nil {
		for _, pk := range prevKeys {
			pub, err := pk.Key.PublicKey()
			if err == nil {
				set.AddKey(pub)
			}
		}
	}

	return set, nil
}

func (km *KeyManager) EncryptPayload(payload []byte) ([]byte, error) {
	activeKey, _, err := km.storage.GetActiveKey()
	if err != nil || activeKey == nil {
		return nil, fmt.Errorf("no active key available")
	}

	// For JWE, we typically use the public part of the key.
	pubKey, err := activeKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// JWE encryption
	// - Algorithm: ECDH-ES + A256KW
	// - Content Encryption: A256GCM
	encrypted, err := jwe.Encrypt(
		payload,
		jwe.WithJSON(),
		jwe.WithKey(jwa.ECDH_ES_A256KW(), pubKey),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt payload: %w", err)
	}
	return encrypted, nil
}

func (km *KeyManager) DecryptPayload(encrypted []byte) ([]byte, error) {
	activeKey, _, err := km.storage.GetActiveKey()
	if err != nil || activeKey == nil {
		return nil, fmt.Errorf("no active key available")
	}
	// For ECDH-ES, we need the private key:
	decrypted, err := jwe.Decrypt(
		encrypted,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), activeKey),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}
	return decrypted, nil
}
