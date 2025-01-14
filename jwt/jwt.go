package jwt

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

// JWTService provides methods to issue and verify encrypted and signed JWTs.
type JWTService struct {
	keyManager *KeyManager
}

// NewJWTService creates a new JWTService instance with the given KeyManager.
func NewJWTService(km *KeyManager) *JWTService {
	return &JWTService{
		keyManager: km,
	}
}

// IssueJWT creates a new JWT with the provided claims and expiration duration,
// signs it using the active key, then encrypts it using JWE with the active key.
func (s *JWTService) IssueJWT(claims map[string]interface{}, expiration time.Duration) ([]byte, error) {
	// Initialize a new JWT token and set standard claims.
	token := jwt.New()
	now := time.Now()
	token.Set(jwt.IssuedAtKey, now)
	token.Set(jwt.ExpirationKey, now.Add(expiration))

	// Set custom claims provided by the caller.
	for k, v := range claims {
		token.Set(k, v)
	}

	// Retrieve the active key from storage for signing.
	activeKey, _, err := s.keyManager.storage.GetActiveKey()
	if err != nil || activeKey == nil {
		return nil, fmt.Errorf("no active key available for signing")
	}

	// Sign the JWT using ES256 algorithm and the active key.
	signedJWT, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), activeKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign jwt: %w", err)
	}

	// Encrypt the signed JWT using the active JWK.
	encrypted, err := s.keyManager.EncryptPayload(signedJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt jwt: %w", err)
	}
	return encrypted, nil
}

// VerifyJWT decrypts the provided encrypted JWT, verifies its signature, 
// parses it, and returns the JWT token. It returns an error if any step fails.
func (s *JWTService) VerifyJWT(encryptedJWT []byte) (jwt.Token, error) {
	// Retrieve the active key from storage for verification.
	activeKey, _, err := s.keyManager.storage.GetActiveKey()
	if err != nil || activeKey == nil {
		return nil, fmt.Errorf("no active key available for verification")
	}

	// Decrypt the encrypted JWT using the active private key.
	decryptedBytes, err := s.keyManager.DecryptPayload(encryptedJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt jwt: %w", err)
	}

	// Parse the decrypted JWT bytes into a token and verify its signature.
	pubKey, err := activeKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("can not get public key from private key")
	}
	token, err := jwt.Parse(decryptedBytes, jwt.WithKey(jwa.ES256(), pubKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse or verify jwt: %w", err)
	}
	return token, nil
}
