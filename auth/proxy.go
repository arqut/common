package auth

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/arqut/common/api"
	"github.com/arqut/common/strcase"
	"github.com/arqut/common/types"
	"github.com/gofiber/fiber/v2"
)

func ProxyAuthMiddleware(finalized ...bool) fiber.Handler {
	isFinalized := true
	if len(finalized) > 0 {
		isFinalized = finalized[0]
	}

	return func(ctx *fiber.Ctx) error {
		// Check if the required header "x-user-id" exists.
		userID := ctx.Get("x-user-id")
		if userID == "" {
			if isFinalized {
				return api.ErrorUnauthorizedResp(ctx, "Unauthorized: Missing x-user-id header")
			} else {
				return errors.New("missing x-user-id header")
			}
		}

		// Collect all headers that have the prefix "x-user-".
		userData := make(map[string]any)
		ctx.Request().Header.VisitAll(func(key, value []byte) {
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
		acc := &AuthTokenData{}
		jsonStr, _ := json.Marshal(userData)
		_ = json.Unmarshal(jsonStr, acc)

		// keep token
		token := ExtractToken(ctx, "header:Authorization,query:auth_token,cookie:jwt")
		acc.Meta = &types.Map{
			"token": token,
		}

		ctx.Locals("account", acc)
		ctx.Locals("authToken", token)

		// Proceed to the next middleware or final handler.
		return ctx.Next()
	}
}

func IsAdminMiddleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if IsAdmin(ctx) {
			return ctx.Next()
		}
		return api.ErrorUnauthorizedResp(ctx, "Unauthorized")
	}
}

func IsAdmin(ctx *fiber.Ctx) bool {
	if acc := ctx.Locals("account"); acc != nil {
		return acc.(*AuthTokenData).IsAdmin
	}
	return false
}
