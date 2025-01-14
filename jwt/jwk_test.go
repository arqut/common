package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestKeyManager_RotationAndPublicKeys(t *testing.T) {
	storage := NewInMemoryStorage()
	km := NewKeyManager(storage, 500*time.Millisecond, 2) // short rotation period for testing

	// 1) Initially, no keys. So InitKeysIfNeeded => generate a new key
	err := km.InitKeysIfNeeded()
	require.NoError(t, err)

	// Confirm we have an active key
	activeKey, expiry, err := storage.GetActiveKey()
	require.NoError(t, err)
	require.NotNil(t, activeKey)
	require.False(t, expiry.IsZero())
	// No previous keys yet
	prevKeys, err := storage.GetPreviousKeys()
	require.NoError(t, err)
	require.Empty(t, prevKeys)

	// 2) Key should expire soon. Wait and see if MustRotateNow becomes true
	// For demonstration, we wait a bit, then check MustRotateNow
	time.Sleep(600 * time.Millisecond)

	rotateNow, err := km.MustRotateNow()
	require.NoError(t, err)
	require.True(t, rotateNow, "key should be expired by now")

	// 3) Rotate: old active -> previous, new active
	err = km.RotateKey()
	require.NoError(t, err)

	// Check that we now have 1 old key, 1 new active key
	newActiveKey, newExpiry, err := storage.GetActiveKey()
	require.NoError(t, err)
	require.NotNil(t, newActiveKey)
	require.False(t, newExpiry.IsZero())
	require.NotEqual(t, activeKey, newActiveKey, "active key should have changed")

	prevKeys, err = storage.GetPreviousKeys()
	require.NoError(t, err)
	require.Len(t, prevKeys, 1)
	require.Equal(t, activeKey, prevKeys[0].Key, "old active should now be in previous keys")

	// 4) Rotate again to test "keep only 2 old keys"
	// We already have 1 old key. After rotating again, we'll have 2 old keys.
	time.Sleep(600 * time.Millisecond)
	rotateNow, err = km.MustRotateNow()
	require.NoError(t, err)
	require.True(t, rotateNow)
	err = km.RotateKey()
	require.NoError(t, err)

	// Now we should have 2 old keys
	prevKeys, err = storage.GetPreviousKeys()
	require.NoError(t, err)
	require.Len(t, prevKeys, 2)

	// 5) One more rotation => should prune the oldest, keeping only 2
	time.Sleep(600 * time.Millisecond)
	rotateNow, err = km.MustRotateNow()
	require.NoError(t, err)
	require.True(t, rotateNow)
	err = km.RotateKey()
	require.NoError(t, err)

	prevKeys, err = storage.GetPreviousKeys()
	require.NoError(t, err)
	require.Len(t, prevKeys, 2, "prune should keep only 2 old keys")

	// 6) GetPublicJWKSet should include 1 active public key + 2 old public keys => 3 total
	publicSet, err := km.GetPublicJWKSet()
	require.NoError(t, err)
	require.Equal(t, 3, publicSet.Len(), "public set includes active + 2 previous")
}

func TestKeyManager_EncryptDecrypt(t *testing.T) {
	storage := NewInMemoryStorage()
	km := NewKeyManager(storage, 10*time.Second, 2)

	// Initialize
	err := km.InitKeysIfNeeded()
	require.NoError(t, err)

	message := []byte("hello world")

	// Encrypt
	encrypted, err := km.EncryptPayload(message)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	// Decrypt
	decrypted, err := km.DecryptPayload(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, decrypted)
}

func TestKeyManager_EncryptDecryptJWT(t *testing.T) {
	storage := NewInMemoryStorage()
	km := NewKeyManager(storage, 10*time.Second, 2)

	// Ensure we have an active key generated
	err := km.InitKeysIfNeeded()
	require.NoError(t, err, "InitKeysIfNeeded should succeed")

	// 1) Create a new JWT token with some example claims
	token, err := jwt.NewBuilder().
		Issuer("TestIssuer").
		Subject("user@example.com").
		Claim("role", "admin").
		Build()
	require.NoError(t, err, "JWT creation should succeed")

	// 2) Serialize the JWT to JSON so we have a plain []byte payload
	plaintext, err := json.Marshal(token)
	require.NoError(t, err, "marshaling JWT to JSON should succeed")

	// 3) Encrypt the JSON payload using KeyManager
	ciphertext, err := km.EncryptPayload(plaintext)
	require.NoError(t, err, "encryption should succeed")
	require.NotEmpty(t, ciphertext, "ciphertext should not be empty")

	// 4) Decrypt it back
	decrypted, err := km.DecryptPayload(ciphertext)
	require.NoError(t, err, "decryption should succeed")
	require.NotEmpty(t, decrypted, "decrypted data should not be empty")

	// 5) Parse the decrypted JSON back into a JWT without verification
	parsedToken, err := jwt.Parse(decrypted,
		jwt.WithVerify(false),   // Skip signature verification
		jwt.WithValidate(false), // Optionally skip claim validation
	)
	require.NoError(t, err, "parsing JWT from JSON should succeed")

	// 6) Verify that claims match what we put in
	issuer, issuerExists := parsedToken.Issuer()
	require.True(t, issuerExists, "issuer claim should be present")
	require.Equal(t, "TestIssuer", issuer, "issuer should match")

	subject, subjectExists := parsedToken.Subject()
	require.True(t, subjectExists, "subject claim should be present")
	require.Equal(t, "user@example.com", subject, "subject should match")

	// Check the custom claim with correct pointer usage
	var roleVal string
	err = parsedToken.Get("role", &roleVal) // Pass pointer to roleVal
	require.NoError(t, err, "role claim retrieval should succeed")
	require.Equal(t, "admin", roleVal, "role should be 'admin'")
}
