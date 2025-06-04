package main

import (
	"AdminGo/internal/handler"
	"AdminGo/pkg/database"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	_ "AdminGo/docs"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"AdminGo/AdminGo/proto/authpb"
	authgrpc "AdminGo/internal/grpc"
	"net"

	"google.golang.org/grpc"
)

// @title AdminGo API
// @version 1.0
// @description Документация для AdminGo API.
// @host localhost:8081
// @BasePath /
func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		logger.Fatal("не удалось инициализировать логгер: %v", zap.Error(err))
	}
	defer logger.Sync()
	db := database.ConnectDB(logger)
	defer db.Close()

	h := handler.NewHandler(db, logger)

	go func() {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			logger.Fatal("failed to listen: %v", zap.Error(err))
		}

		grpcServer := grpc.NewServer()
		authpb.RegisterAuthServiceServer(grpcServer, authgrpc.NewAuthGRPCServer(db))
		logger.Info("GRPC server listening on :50051")
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatal("failed to serve: %v", zap.Error(err))
		}
	}()
	r := gin.Default()

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.Use(CORSMiddleware())
	r.POST("/api/register", h.RegisterHandler)
	r.POST("/api/login", h.LoginHandler)
	r.POST("/api/refresh", h.RefreshHandler)
	r.GET("/api/profile", h.ProfileHandler)

	err = r.Run(":8081")
	if err != nil {
		logger.Fatal("Server Run Failed: ", zap.Error(err))
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
