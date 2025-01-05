package auth

import (
	"fmt"
	"time"

	"github.com/arqut/common/system"
	"github.com/arqut/common/types"
	"github.com/golang-jwt/jwt/v4"
)

func GenerateToken(data types.Map) (string, error) {
	du, _ := time.ParseDuration(system.Env("JWT_DURATION", "2h"))
	data["iat"] = jwt.NewNumericDate(time.Now())
	data["exp"] = jwt.NewNumericDate(time.Now().Add(du))

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(data))
	token, err := t.SignedString([]byte(system.Env("JWT_SECRET")))
	if err != nil {
		return "", err
	}

	return token, nil
}

func ParseToken(token string) (types.Map, error) {
	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(system.Env("JWT_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok || !t.Valid {
		return nil, fmt.Errorf("token is invalid or expired")
	}

	return types.Map(claims), nil
}
