package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	commonJWT "github.com/arqut/common/jwt"
	"github.com/arqut/common/system"
	"github.com/arqut/common/types"
)

func GenerateToken(keyManager *commonJWT.KeyManager, data types.Map, expiration ...time.Duration) (*string, error) {
	var duration time.Duration
	if len(expiration) > 0 {
		duration = expiration[0]
	} else {
		duration, _ = time.ParseDuration(system.Env("JWT_DURATION", "2h"))
	}


	mashalled_data, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	jweOptions := &commonJWT.JWEOptions{
		ExpiresIn: duration,
		Headers: map[string]interface{}{
			"custom-header": "custom-value",
		},
	}

	token, err := keyManager.IssueJWE(mashalled_data, jweOptions)
	if err != nil {
		return nil, err
	}

	tokenStr := string(token)
	return &tokenStr, nil
}

func ParseToken(keyManager *commonJWT.KeyManager, token string) (*types.Map, error) {
	decrypted, err := keyManager.DecryptJWE([]byte(token))
	if err != nil {
		keyManager.RefreshKeys()
		decrypted, err = keyManager.DecryptJWE([]byte(token))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt token: %w", err)
		}
	}

	dec := json.NewDecoder(bytes.NewReader(decrypted))

	var data types.Map

	// Decode the JSON into the types.Map
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	return &data, nil
}
