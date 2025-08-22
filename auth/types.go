package auth

import (
	"fmt"

	"github.com/arqut/common/api"
	"github.com/arqut/common/http"
	"github.com/arqut/common/system"
	"github.com/arqut/common/types"
)

type AuthTokenData struct {
	ID        uint64     `json:"id" gorm:"primaryKey"`
	PublicID  string     `json:"publicId" gorm:"type:varchar(8);unique"`
	Name      string     `json:"name" gorm:"type:varchar(128);"`
	Email     string     `json:"email" gorm:"type:varchar(128);uniqueIndex"`
	AvatarUrl string     `json:"avatarUrl" gorm:"type:varchar(256)"`
	IsAdmin   bool       `json:"isAdmin"`
	CreatedAt uint64     `json:"createdAt"`
	Meta      *types.Map `json:"meta,omitempty"`
}

type AuthValidateResponse struct {
	Success bool           `json:"success"`
	Data    *AuthTokenData `json:"data,omitempty"`
	Error   *api.ApiError  `json:"error,omitempty"`
}

type AuthRefreshResponse struct {
	Success bool          `json:"success"`
	Data    string        `json:"data,omitempty"`
	Error   *api.ApiError `json:"error,omitempty"`
}

func (acc *AuthTokenData) SID() string {
	return fmt.Sprintf("%d", acc.ID)
}

func (acc *AuthTokenData) GetAuthToken() string {
	meta := *acc.Meta
	if token, ok := meta["token"]; ok {
		return token.(string)
	}
	return ""
}

func (acc *AuthTokenData) SendNotification(targetIds []string, title, body string, data map[string]string) (*api.ApiResponse, error) {
	authApi := system.Env("AUTH_API")
	if authApi == "" {
		return nil, fmt.Errorf("auth api is missing")
	}

	url := authApi + "/notification/send"

	reqData := map[string]any{
		"to":    targetIds,
		"title": title,
		"body":  body,
	}

	if data != nil {
		reqData["data"] = data
		reqData["action"] = "OPEN_ITEM"
	}

	res := &api.ApiResponse{}
	if err := http.Post(url, reqData, res, "Authorization", "Bearer "+acc.GetAuthToken()); err != nil {
		return nil, err
	}

	return res, nil
}
