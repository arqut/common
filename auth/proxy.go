package auth

import (
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
		userData := make(map[string]string)
		c.Request().Header.VisitAll(func(key, value []byte) {
			headerKey := string(key)
			if strings.HasPrefix(headerKey, "X-User-") {
				key := strings.TrimPrefix(headerKey, "X-User-")
				userData[strcase.LowerCamelCase(key)] = string(value)
			}
		})
		// Store the claims in the context so that they can be accessed in downstream handlers.
		uiID, _ := strconv.Atoi(userID)
		c.Locals("uiID", uint64(uiID))
		c.Locals("usID", userID)
		c.Locals("userData", userData)

		// Proceed to the next middleware or final handler.
		return c.Next()
	}
}

func IsAdmin(c *fiber.Ctx) bool {
	if userData := c.Locals("userData"); userData != nil {
		if val, ok := userData.(map[string]interface{})["isAdmin"]; ok && val == "true" {
			return val.(bool)
		}
	}
	return false
}
