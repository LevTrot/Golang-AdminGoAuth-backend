package grpc

import (
	"AdminGo/AdminGo/proto/authpb"
	"AdminGo/internal/domain"
	"context"
	"log"

	"github.com/jmoiron/sqlx"
)

type AuthGRPCServer struct {
	authpb.UnimplementedAuthServiceServer
	DB *sqlx.DB
}

func NewAuthGRPCServer(db *sqlx.DB) *AuthGRPCServer {
	return &AuthGRPCServer{DB: db}
}

func (s *AuthGRPCServer) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	claims, err := domain.ParseAccessToken(req.GetToken())
	if err != nil {
		return &authpb.ValidateTokenResponse{
			Valid: false,
			Error: "invalid token",
		}, nil
	}

	var role string
	err = s.DB.Get(&role, "SELECT role FROM auth_schema.users WHERE id=$1", claims.UserID)
	if err != nil {
		log.Println("Failed to fetch role:", err)
		return &authpb.ValidateTokenResponse{
			Valid: false,
			Error: "could not fetch role",
		}, nil
	}

	return &authpb.ValidateTokenResponse{
		UserId:   int32(claims.UserID),
		Username: claims.Username,
		Role:     role,
		Valid:    true,
	}, nil
}
