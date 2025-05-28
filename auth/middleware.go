package auth

import (
	"errors"

	"github.com/arqut/common/api"
	"github.com/arqut/common/cache"
	"github.com/arqut/common/http"
	"github.com/arqut/common/system"
	"github.com/arqut/common/types"
	"github.com/arqut/common/utils"
	"github.com/gofiber/fiber/v2"
)

func RemoteAuthMiddleware(finalized ...bool) fiber.Handler {
	extractTokens := "header:Authorization,query:auth_token"
	return remoteMiddleware(extractTokens)
}

func RemoteAPIKeyMiddleware(finalized ...bool) fiber.Handler {
	extractTokens := "header:Authorization,query:apikey"
	return remoteMiddleware(extractTokens)
}

// RemoteMiddleware accept both auth_token or apikey
func RemoteMiddleware(finalized ...bool) fiber.Handler {
	extractTokens := "header:Authorization,query:auth_token,query:apikey"
	return remoteMiddleware(extractTokens, finalized...)
}

func remoteMiddleware(extractToken string, finalized ...bool) fiber.Handler {
	isFinalized := true
	if len(finalized) > 0 {
		isFinalized = finalized[0]
	}

	return func(ctx *fiber.Ctx) error {
		token := ExtractToken(ctx, extractToken)
		if token == "" {
			if isFinalized {
				return api.ErrorUnauthorizedResp(ctx, "Missing auth token or apikey")
			} else {
				return errors.New("missing auth token or apikey")
			}
		}

		acc, err := RemoteAccount(token)
		if err != nil {
			if isFinalized {
				return api.ErrorUnauthorizedResp(ctx, err.Error())
			} else {
				return err
			}
		}

		// keep token
		acc.Meta = &types.Map{
			"token": token,
		}

		ctx.Locals("account", acc)
		ctx.Locals("authToken", token)

		return ctx.Next()
	}
}

func RemoteAccount(token string) (acc *AuthTokenData, err error) {
	acc = &AuthTokenData{}
	err = cache.GetObj(token, acc)

	if err != nil || acc.ID == 0 {
		err = nil
		res := &AuthValidateResponse{}
		err := http.Get(system.Env("AUTH_API")+"/auth/validate", res, "Authorization", "Bearer "+token)
		if err != nil {
			return nil, err
		}
		if !res.Success {
			return nil, errors.New(res.Error.Message)
		}

		acc = res.Data
		acc.Meta = &types.Map{
			"token": token,
		}
		duration, _ := utils.ParseDuration(system.Env("AUTH_CACHE_DURATION", "1h"))
		cache.SetObj(token, acc, duration)
	}

	return acc, err
}
