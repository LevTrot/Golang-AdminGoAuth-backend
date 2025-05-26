package database

import (
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var db *sqlx.DB

// Подключение БД
func ConnectDB() *sqlx.DB {
	dsn := "postgres://postgres:mysecretpassword@localhost:5432/postgres?sslmode=disable"
	conn, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		log.Fatalln("DB connection failed: ", err)
	}
	db = conn
	return conn
}
