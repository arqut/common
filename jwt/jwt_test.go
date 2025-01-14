package jwt

import (
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func TestIssueAndVerifyJWT(t *testing.T) {
	// Initialize storage, key manager, and JWT service.
	storage := NewInMemoryStorage()
	keyManager := NewKeyManager(storage, time.Hour, 5)
	if err := keyManager.InitKeysIfNeeded(); err != nil {
		t.Fatalf("Failed to initialize keys: %s", err)
	}
	jwtService := NewJWTService(keyManager)

	// Define custom claims for the JWT.
	claims := map[string]interface{}{
		"sub":   "1234567890",
		"name":  "John Doe",
		"admin": true,
	}

	// Issue an encrypted JWT.
	encryptedToken, err := jwtService.IssueJWT(claims, time.Hour)
	if err != nil {
		t.Fatalf("IssueJWT failed: %s", err)
	}
	if len(encryptedToken) == 0 {
		t.Fatal("IssueJWT returned an empty token")
	}

	// Verify the encrypted JWT.
	token, err := jwtService.VerifyJWT(encryptedToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %s", err)
	}

	// Validate that all custom claims are present and correct.
	for k, expected := range claims {
		var got interface{}
		if err := token.Get(k, &got); err != nil {
			t.Errorf("Expected claim %q not found: %s", k, err)
			continue
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("Claim %q = %v, want %v", k, got, expected)
		}
	}

	// Optionally, check standard claims like IssuedAt and Expiration.
	var issuedAt time.Time
	if err := token.Get(jwt.IssuedAtKey, &issuedAt); err != nil {
		t.Error("IssuedAt claim not found or invalid:", err)
	} else {
		if time.Since(issuedAt) < 0 {
			t.Error("IssuedAt time is in the future")
		}
	}

	var expiration time.Time
	if err := token.Get(jwt.ExpirationKey, &expiration); err != nil {
		t.Error("Expiration claim not found or invalid:", err)
	} else {
		if time.Until(expiration) <= 0 {
			t.Error("Expiration time is not in the future")
		}
	}
}
