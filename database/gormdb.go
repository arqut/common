package database

import (
	"fmt"

	"github.com/arqut/common/system"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	DB  *gorm.DB
	dbs = map[string]*gorm.DB{}
)

func ConnDB(conn string) *gorm.DB {
	if db, ok := dbs[conn]; ok {
		return db
	}
	return nil
}

func ConnMySqlDB(conn string, envPrefix string) *gorm.DB {
	DB_PORT := system.Env(envPrefix + "_PORT")
	if DB_PORT == "" {
		DB_PORT = "3306"
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", system.Env(envPrefix+"_USER"), system.Env(envPrefix+"_PASS"), system.Env(envPrefix+"_HOST"), DB_PORT, system.Env(envPrefix+"_NAME"))

	// NOTE:
	// To handle time.Time correctly, you need to include parseTime as a parameter. (more parameters)
	// To fully support UTF-8 encoding, you need to change charset=utf8 to charset=utf8mb4. See this article for a detailed explanation
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.LogLevel(system.EnvInt(envPrefix+"_LOG_LEVEL", 3))),
	})
	if err != nil {
		system.Logger.Panic("Failed to connect to database")
	}
	system.Logger.Infof("Connect to MySQL Database: '%s'\n", system.Env("DB_NAME"))
	dbs[conn] = db
	return db
}

func InitMySqlDB() {
	DB = ConnMySqlDB("main", "DB")
}

func ConnPostgresDB(conn string, envPrefix string) *gorm.DB {
	DB_PORT := system.Env(envPrefix + "_PORT")
	if DB_PORT == "" {
		DB_PORT = "5432"
	}
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", system.Env(envPrefix+"_HOST"), system.Env(envPrefix+"_USER"), system.Env(envPrefix+"_PASS"), system.Env(envPrefix+"_NAME"), DB_PORT)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.LogLevel(system.EnvInt(envPrefix+"_LOG_LEVEL", 3))),
	})
	if err != nil {
		system.Logger.Panic("Failed to connect to database")
	}
	system.Logger.Infof("Connect to Postgres Database: '%s'", system.Env("DB_NAME"))
	dbs[conn] = db
	return db
}

func InitPostgresDB() {
	DB = ConnPostgresDB("main", "DB")
}
