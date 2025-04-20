package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	commonJWT "github.com/arqut/common/jwt"
	"github.com/arqut/common/system"
	"github.com/arqut/common/utils"
)

func GenerateToken(keyManager *commonJWT.KeyManager, data *AuthTokenData, expiration ...time.Duration) (*string, error) {
	var duration time.Duration
	if len(expiration) > 0 {
		duration = expiration[0]
	} else {
		duration, _ = utils.ParseDuration(system.Env("JWT_DURATION", "2h"))
	}

	mashalledData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	jweOptions := &commonJWT.JWEOptions{
		ExpiresIn: duration,
		// Headers: map[string]interface{}{
		// 	"custom-header": "custom-value",
		// },
	}

	token, err := keyManager.IssueJWE(mashalledData, jweOptions)
	if err != nil {
		return nil, err
	}

	tokenStr := string(token)
	return &tokenStr, nil
}

func ParseToken(keyManager *commonJWT.KeyManager, token string) (*AuthTokenData, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}

	decrypted, err := keyManager.DecryptJWE([]byte(token))
	if err != nil {
		keyManager.RefreshKeys()
		decrypted, err = keyManager.DecryptJWE([]byte(token))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt token: %w", err)
		}
	}

	dec := json.NewDecoder(bytes.NewReader(decrypted))

	data := &AuthTokenData{}

	// Decode the JSON into the types.Map
	if err := dec.Decode(data); err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	return data, nil
}

func ParseTokenForAudience(keyManager *commonJWT.KeyManager, token string, audience string) (*AuthTokenData, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}

	decrypted, err := keyManager.DecryptJWEForAudience([]byte(token), audience)
	if err != nil {
		keyManager.RefreshKeys()
		decrypted, err = keyManager.DecryptJWE([]byte(token))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt token: %w", err)
		}
	}

	dec := json.NewDecoder(bytes.NewReader(decrypted))

	data := &AuthTokenData{}

	// Decode the JSON into the types.Map
	if err := dec.Decode(data); err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	return data, nil
}

func IsApiKey(token string) bool {
	dotIndex := strings.IndexByte(token, '.')
	if dotIndex == -1 || dotIndex != 8 || dotIndex == len(token)-1 {
		return false
	}

	return true
}
