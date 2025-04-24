package main

import (
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	db := ConnectDB()
	defer db.Close()

	r := gin.Default()

	r.Use(cors.Default())
	r.POST("api/register", RegisterHandler)
	r.POST("api/login", LoginHandler)

	err := r.Run(":8080")
	if err != nil {
		log.Fatal("Server Run Failed: ", err)
	}
}
