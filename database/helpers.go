package database

import (
	"math"

	"github.com/arqut/common/api"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func Ordering(c *fiber.Ctx, meta ...*api.Map) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		orderBy := c.Query("orderBy")
		if orderBy != "" {
			ordering := "DESC"
			if c.Query("ordering") == "ASC" {
				ordering = "ASC"
			}
			if len(meta) > 0 {
				(*meta[0])[orderBy] = ordering
			}
			return db.Order(orderBy + " " + ordering)
		}
		return db
	}
}

func Paginate(c *fiber.Ctx, meta ...*api.Pagination) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		page := c.QueryInt("page", 1)
		perPage := c.QueryInt("perPage", 15)

		if len(meta) > 0 {
			meta[0].Page = page
			meta[0].PerPage = perPage
			if meta[0].Total > 0 {
				meta[0].TotalPages = int(math.Ceil(float64(meta[0].Total) / float64(meta[0].PerPage)))
			}
		}
		offset := (page - 1) * perPage
		return db.Offset(offset).Limit(perPage)
	}
}
