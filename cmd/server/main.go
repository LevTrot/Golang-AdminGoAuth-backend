package main

import (
	"AdminGo/internal/handler"
	"AdminGo/pkg/database"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"AdminGo/AdminGo/proto/authpb"
	authgrpc "AdminGo/internal/grpc"
	"net"

	"google.golang.org/grpc"
)

func main() {
	db := database.ConnectDB()
	defer db.Close()

	h := handler.NewHandler(db)

	go func() {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}

		grpcServer := grpc.NewServer()
		authpb.RegisterAuthServiceServer(grpcServer, authgrpc.NewAuthGRPCServer(db))
		log.Println("GRPC server listening on :50051")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

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
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:5174")
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
