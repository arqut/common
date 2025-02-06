package auth

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/arqut/common/api"
	"github.com/arqut/common/strcase"
	"github.com/gofiber/fiber/v2"
)

func ProxyAuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check if the required header "x-user-id" exists.
		userID := c.Get("x-user-id")
		if userID == "" {
			return api.ErrorUnauthorizedResp(c, "Unauthorized: Missing x-user-id header")
		}

		// Collect all headers that have the prefix "x-user-".
		userData := make(map[string]interface{})
		c.Request().Header.VisitAll(func(key, value []byte) {
			headerKey := string(key)
			if strings.HasPrefix(headerKey, "X-User-") {
				key := strcase.LowerCamelCase(strings.TrimPrefix(headerKey, "X-User-"))
				if key == "id" {
					id, _ := strconv.Atoi(string(value))
					userData[key] = uint64(id)
				} else if key == "isAdmin" {
					userData[key] = string(value) == "true"
				} else {
					userData[key] = string(value)
				}
			}
		})

		// convert to AuthTokenData
		authData := &AuthTokenData{}
		jsonStr, _ := json.Marshal(userData)
		_ = json.Unmarshal(jsonStr, authData)

		// Store the claims in the context so that they can be accessed in downstream handlers.
		c.Locals("uiID", authData.ID)
		c.Locals("usID", userID)
		c.Locals("authData", authData)

		// Proceed to the next middleware or final handler.
		return c.Next()
	}
}

func IsAdmin(c *fiber.Ctx) bool {
	if authData := c.Locals("userData"); authData != nil {
		return authData.(*AuthTokenData).IsAdmin
	}
	return false
}
