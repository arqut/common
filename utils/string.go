package utils

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

const (
	idLength  = 8
	alphabets = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func GenerateRandomString(length int) (string, error) {
	id := make([]byte, length)

	// Generate prefix
	for i := 0; i < length; i++ {
		char, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabets))))
		if err != nil {
			return "", err
		}
		id[i] = alphabets[char.Int64()]
	}

	return string(id), nil
}

func GenerateID() (string, error) {
	return GenerateRandomString(idLength)
}

func StringToInt(val string) int {
	i, err := strconv.Atoi(val)
	if err != nil {
		return 0
	}
	return i
}

// ToCamelCase
// This will convert snake case to camelCased
// @return camelCased string, number of parts
func ToCamelCase(str string, splitter rune) (string, int) {
	parts := strings.Split(str, "_")
	for index := range parts {
		if index != 0 {
			parts[index] = strings.Title(strings.ToLower(parts[index]))
		} else {
			parts[index] = strings.ToLower(parts[index])
		}
	}
	return strings.Join(parts, ""), len(parts)
}

// CamelCaseToSnakeCase
// This will convert camelCase to snake_cased
// @return snakeCased string, number of parts
func ToSnakeCase(inputCamelCaseStr string) (string, int) {
	// Regex from https://www.golangprograms.com/split-a-string-at-uppercase-letters-using-regular-expression-in-golang.html
	re := regexp.MustCompile(`[A-z][^A-Z]*`)
	parts := re.FindAllString(inputCamelCaseStr, -1)
	for index := range parts {
		parts[index] = strings.ToLower(parts[index])
	}
	return strings.Join(parts, "_"), len(parts)
}

func ToString(data interface{}) string {
	switch data.(type) {
	case int:
		return fmt.Sprintf("%d", data)
	case float32:
	case float64:
		return fmt.Sprintf("%f", data)
	case string:
		return data.(string)
	default:
	}
	text, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return ""
	}
	return string(text)
}

func HashKey(key string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(key)))
}
