package auth

import (
	"os"
	"testing"
	"time"

	commonJWT "github.com/arqut/common/jwt"
	"github.com/arqut/common/system"
	"github.com/arqut/common/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Initialize system.Logger with a simple logger.
	// Adjust the configuration as needed.
	os.Setenv("SYS_LOG_LEVEL", "INFO")
	
	system.InitLogger("test_logger")

	// Run the tests.
	code := m.Run()

	// Exit with the appropriate code.
	os.Exit(code)
}

// Helper function to set up a KeyManager with an InMemoryKeyStore
func setupKeyManager(t *testing.T, rotationPeriod time.Duration) *commonJWT.KeyManager {
	store := commonJWT.NewInMemoryKeyStore()
	km, err := commonJWT.NewIssuerKeyManager(rotationPeriod, store)
	require.NoError(t, err, "Failed to initialize KeyManager")

	return km
}

// TestGenerateAndParseToken_Success tests the successful generation and parsing of a token
func TestGenerateAndParseToken_Success(t *testing.T) {
	rotationPeriod := 24 * time.Hour
	km := setupKeyManager(t, rotationPeriod)

	// Sample data to encode in the token
	data := types.Map{
		"user_id": float64(12345), // Changed from int to float64
		"role":    "admin",
		"email":   "user@example.com",
	}

	// Generate the token
	token, err := GenerateToken(km, data)
	require.NoError(t, err, "GenerateToken should not return an error")
	assert.NotNil(t, token, "Generated token should not be nil")

	// Parse the token
	parsedData, err := ParseToken(km, *token)
	require.NoError(t, err, "ParseToken should not return an error")
	assert.NotNil(t, parsedData, "Parsed data should not be nil")

	// Verify that the parsed data matches the original data
	assert.Equal(t, data, *parsedData, "Parsed data should match the original data")
}

// TestParseToken_Expired tests parsing of an expired token
func TestParseToken_Expired(t *testing.T) {
	rotationPeriod := 24 * time.Hour
	km := setupKeyManager(t, rotationPeriod)

	// Sample data to encode in the token
	data := types.Map{
		"user_id": float64(67890), // Changed from int to float64
		"role":    "user",
	}

	// Generate the token with a short expiration time
	shortDuration := 1 * time.Second
	token, err := GenerateToken(km, data, shortDuration)
	require.NoError(t, err, "GenerateToken should not return an error")
	assert.NotNil(t, token, "Generated token should not be nil")

	// Wait for the token to expire
	time.Sleep(2 * time.Second)

	// Attempt to parse the expired token
	parsedData, err := ParseToken(km, *token)
	require.Error(t, err, "ParseToken should return an error for expired token")
	assert.Nil(t, parsedData, "Parsed data should be nil for expired token")
}

// TestParseToken_InvalidToken tests parsing of an invalid token format
func TestParseToken_InvalidToken(t *testing.T) {
	rotationPeriod := 24 * time.Hour
	km := setupKeyManager(t, rotationPeriod)

	invalidToken := "this.is.not.a.valid.token"

	parsedData, err := ParseToken(km, invalidToken)
	require.Error(t, err, "ParseToken should return an error for invalid token format")
	assert.Nil(t, parsedData, "Parsed data should be nil for invalid token")
}

// TestParseToken_TamperedToken tests parsing of a tampered token
func TestParseToken_TamperedToken(t *testing.T) {
	rotationPeriod := 24 * time.Hour
	km := setupKeyManager(t, rotationPeriod)

	// Sample data to encode in the token
	data := types.Map{
		"user_id": float64(54321), // Changed from int to float64
		"role":    "editor",
	}

	// Generate the token
	token, err := GenerateToken(km, data)
	require.NoError(t, err, "GenerateToken should not return an error")
	assert.NotNil(t, token, "Generated token should not be nil")

	// Tamper with the token by altering a character
	tamperedToken := *token
	if len(tamperedToken) > 10 {
		tamperedToken = tamperedToken[:10] + "X" + tamperedToken[11:]
	} else {
		tamperedToken = tamperedToken + "X"
	}

	// Attempt to parse the tampered token
	parsedData, err := ParseToken(km, tamperedToken)
	require.Error(t, err, "ParseToken should return an error for tampered token")
	assert.Nil(t, parsedData, "Parsed data should be nil for tampered token")
}

// TestGenerateToken_CustomExpiration tests generating a token with a custom expiration duration
func TestGenerateToken_CustomExpiration(t *testing.T) {
	rotationPeriod := 24 * time.Hour
	km := setupKeyManager(t, rotationPeriod)

	// Sample data to encode in the token
	data := types.Map{
		"session_id": "abc123",
		"permissions": []interface{}{"read", "write"}, // Changed from []string to []interface{}
	}

	// Custom expiration duration
	customDuration := 5 * time.Hour

	// Generate the token with custom expiration
	token, err := GenerateToken(km, data, customDuration)
	require.NoError(t, err, "GenerateToken should not return an error")
	assert.NotNil(t, token, "Generated token should not be nil")

	// Parse the token
	parsedData, err := ParseToken(km, *token)
	require.NoError(t, err, "ParseToken should not return an error")
	assert.NotNil(t, parsedData, "Parsed data should not be nil")

	// Verify that the parsed data matches the original data
	assert.Equal(t, data, *parsedData, "Parsed data should match the original data")
}

// TestGenerateToken_DefaultExpiration tests generating a token with default expiration duration
func TestGenerateToken_DefaultExpiration(t *testing.T) {
	rotationPeriod := 24 * time.Hour
	km := setupKeyManager(t, rotationPeriod)

	// Sample data to encode in the token
	data := types.Map{
		"event": "login",
		"time":  float64(time.Now().Unix()), // Changed from int64 to float64
	}

	// Generate the token without specifying expiration
	token, err := GenerateToken(km, data)
	require.NoError(t, err, "GenerateToken should not return an error")
	assert.NotNil(t, token, "Generated token should not be nil")

	// Parse the token
	parsedData, err := ParseToken(km, *token)
	require.NoError(t, err, "ParseToken should not return an error")
	assert.NotNil(t, parsedData, "Parsed data should not be nil")

	// Verify that the parsed data matches the original data
	assert.Equal(t, data, *parsedData, "Parsed data should match the original data")
}
