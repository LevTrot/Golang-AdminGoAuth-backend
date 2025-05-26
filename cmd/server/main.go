package main

import (
	"AdminGo/internal/handler"
	"AdminGo/pkg/database"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	db := database.ConnectDB()
	defer db.Close()

	h := handler.NewHandler(db)

	r := gin.Default()

	r.Use(CORSMiddleware())
	r.POST("/api/register", h.RegisterHandler)
	r.POST("/api/login", h.LoginHandler)
	r.POST("/api/refresh", h.RefreshHandler)
	r.GET("/api/profile", h.ProfileHandler)

	err := r.Run(":8081")
	if err != nil {
		log.Fatal("Server Run Failed: ", err)
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
