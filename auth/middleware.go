package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/arqut/common/api"
	"github.com/arqut/common/cache"
	"github.com/arqut/common/http"
	"github.com/arqut/common/system"
	"github.com/gofiber/fiber/v2"
)

func RemoteAuthMiddleware() fiber.Handler {
	extractTokens := "header:Authorization,query:auth_token"
	return remoteMiddleware(extractTokens)
}

func RemoteAPIKeyMiddleware() fiber.Handler {
	extractTokens := "header:Authorization,query:apikey"
	return remoteMiddleware(extractTokens)
}

// RemoteMiddleware accept both auth_token or apikey
func RemoteMiddleware() fiber.Handler {
	extractTokens := "header:Authorization,query:auth_token,query:apikey"
	return remoteMiddleware(extractTokens)
}

func remoteMiddleware(extractTokens ...string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		token := ExtractToken(ctx, extractTokens...)
		if token == "" {
			return api.ErrorUnauthorizedResp(ctx, "Missing auth token or apikey")
		}

		act, err := RemoteAccount(token)
		if err != nil {
			return api.ErrorUnauthorizedResp(ctx, err.Error())
		}

		ctx.Locals("authToken", token)
		ctx.Locals("account", act)
		ctx.Locals("uiID", act.ID)
		ctx.Locals("usID", fmt.Sprintf("%d", act.ID))

		return ctx.Next()
	}
}

func RemoteAccount(token string) (act *Account, err error) {
	act = &Account{}
	err = cache.GetObj(token, act)

	if err != nil || act.ID == 0 {
		system.Logger.Errorf("[common/auth] caching error: %v", err)
		err = nil
		resp := &AuthAccountResponse{}
		err := http.Get(system.Env("AUTH_API")+"/auth/account", resp, "Authorization", "Bearer "+token)
		if err != nil {
			return nil, err
		}
		if !resp.Success {
			return nil, errors.New(resp.Error.Message)
		}
		act = resp.Data
		duration, _ := time.ParseDuration(system.Env("AUTH_CACHE_DURATION", "1h"))
		cache.SetObj(token, act, duration)
	}

	return act, err
}
