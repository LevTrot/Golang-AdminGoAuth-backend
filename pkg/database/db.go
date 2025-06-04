package database

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func ConnectDB(logger *zap.Logger) *sqlx.DB {
	dsn := "postgres://postgres:mysecretpassword@localhost:5432/postgres?sslmode=disable"
	conn, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		logger.Fatal("DB connection failed: ", zap.Error(err))
	}
	logger.Info("Succesful connection to DB")
	return conn
}
