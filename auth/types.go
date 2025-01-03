package auth

import (
	"github.com/tphan267/common/api"
	"github.com/tphan267/common/types"
)

type Account struct {
	ID        uint64     `json:"id" gorm:"primaryKey"`
	Name      string     `json:"name" gorm:"type:varchar(128);"`
	Email     string     `json:"email" gorm:"type:varchar(128);uniqueIndex"`
	AvatarUrl string     `json:"avatarUrl" gorm:"type:varchar(256)"`
	State     int        `json:"state"`
	IsAdmin   bool       `json:"isAdmin"`
	Meta      *types.Map `json:"meta,omitempty"`
}

type AuthAccountResponse struct {
	Success bool          `json:"success"`
	Data    *Account      `json:"data,omitempty"`
	Error   *api.ApiError `json:"error,omitempty"`
}

type AuthRefreshResponse struct {
	Success bool          `json:"success"`
	Data    string        `json:"data,omitempty"`
	Error   *api.ApiError `json:"error,omitempty"`
}
