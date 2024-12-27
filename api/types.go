package api

import (
	"time"

	"github.com/tphan267/common/types"
)

type Map types.Map

type Pagination struct {
	Page       int `json:"page"`
	PerPage    int `json:"perPage"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
}

type ApiResponseMeta struct {
	RequestID  string      `json:"requestId,omitempty"`
	Timestamp  *time.Time  `json:"timestamp,omitempty"`
	Ordering   *Map        `json:"ordering,omitempty"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

type ApiError struct {
	Code    int         `json:"code,omitempty"`
	Message string      `json:"message,omitempty"`
	Detail  interface{} `json:"detail,omitempty"`
}

type ApiResponse struct {
	Success bool            `json:"success"`
	Data    interface{}     `json:"data,omitempty"`
	Error   ApiError        `json:"error,omitempty"`
	Meta    ApiResponseMeta `json:"meta,omitempty"`
}
