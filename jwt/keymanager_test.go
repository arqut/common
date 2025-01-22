package jwt

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestIssuerModeIssueAndDecrypt(t *testing.T) {
	store := NewInMemoryKeyStore()
	km, err := NewIssuerKeyManager(5*time.Minute, store)
	if err != nil {
		t.Fatalf("Failed to initialize Issuer KeyManager: %v", err)
	}

	payload := []byte("Test payload for issuer mode")
	token, err := km.IssueJWE(payload, &JWEOptions{ExpiresIn: 1 * time.Minute})
	if err != nil {
		t.Fatalf("IssueJWE failed in issuer mode: %v", err)
	}

	decrypted, err := km.DecryptJWE(token)
	if err != nil {
		t.Fatalf("DecryptJWE failed in issuer mode: %v", err)
	}
	if !bytes.Equal(payload, decrypted) {
		t.Errorf("Decrypted payload mismatch. Got %s, want %s", decrypted, payload)
	}
}

func TestValidationOnlyModeRejectsIssuance(t *testing.T) {
	store := NewInMemoryKeyStore()
	keyEntry := KeyEntry{
		Key:    make([]byte, 32),
		Info:   []byte("prepopulated-key"),
		Expiry: time.Now().Add(5 * time.Minute),
	}
	store.SaveKey(keyEntry)

	km, err := NewValidationKeyManager(store)
	if err != nil {
		t.Fatalf("Failed to initialize Validation Only KeyManager: %v", err)
	}

	_, err = km.IssueJWE([]byte("should fail"), &JWEOptions{})
	if err == nil || !strings.Contains(err.Error(), "not allowed in validation only mode") {
		t.Errorf("Expected error for IssueJWE in validation-only mode, got: %v", err)
	}
}

func TestValidationOnlyModeWithoutKeys(t *testing.T) {
	store := NewInMemoryKeyStore()
	_, err := NewValidationKeyManager(store)
	if err == nil || !strings.Contains(err.Error(), "no keys available") {
		t.Errorf("Expected error for ValidationOnly mode with no keys, got: %v", err)
	}
}

func TestValidationOnlyModeDecrypt(t *testing.T) {
	store := NewInMemoryKeyStore()
	issuerKM, err := NewIssuerKeyManager(5*time.Minute, store)
	if err != nil {
		t.Fatalf("Failed to initialize Issuer KeyManager: %v", err)
	}

	payload := []byte("Validation only mode decryption test")
	token, err := issuerKM.IssueJWE(payload, &JWEOptions{ExpiresIn: 1 * time.Minute})
	if err != nil {
		t.Fatalf("IssueJWE failed in issuer mode: %v", err)
	}

	validationKM, err := NewValidationKeyManager(store)
	if err != nil {
		t.Fatalf("Failed to initialize Validation Only KeyManager: %v", err)
	}

	decrypted, err := validationKM.DecryptJWE(token)
	if err != nil {
		t.Fatalf("DecryptJWE failed in validation-only mode: %v", err)
	}
	if !bytes.Equal(payload, decrypted) {
		t.Errorf("Decrypted payload mismatch in validation-only mode. Got %s, want %s", decrypted, payload)
	}
}

func TestValidationOnlyModePreventsRotation(t *testing.T) {
	store := NewInMemoryKeyStore()
	store.SaveKey(KeyEntry{
		Key:    make([]byte, 32),
		Info:   []byte("prepopulated-key"),
		Expiry: time.Now().Add(5 * time.Minute),
	})

	km, err := NewValidationKeyManager(store)
	if err != nil {
		t.Fatalf("Failed to initialize Validation Only KeyManager: %v", err)
	}

	err = km.rotateKey()
	if err == nil || !strings.Contains(err.Error(), "not allowed in validation only mode") {
		t.Errorf("Expected rotation to fail in validation-only mode, got: %v", err)
	}
}
