package auth

import (
	"github.com/arqut/common/api"
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

func (acc *AuthTokenData) GetAuthToken() string {
	meta := *acc.Meta
	if token, ok := meta["token"]; ok {
		return token.(string)
	}
	return ""
}
