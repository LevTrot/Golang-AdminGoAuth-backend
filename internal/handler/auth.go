package handler

import (
	"AdminGo/internal/domain"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	DB     *sqlx.DB
	logger *zap.Logger
}

func NewHandler(db *sqlx.DB, logger *zap.Logger) *Handler {
	return &Handler{DB: db, logger: logger}
}

type User struct {
	ID       int    `db:"id"`
	Username string `db:"username"`
	Email    string `db:"email"`
	Password string `db:"password_hash"`
	Role     string `db:"role"`
}

type RegisterInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password_hash"`
	Role     string `json:"role"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password_hash"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// RegisterHandler регистрирует нового пользователя
// @Summary Register user
// @Tags auth
// @Accept json
// @Produce json
// @Param input body RegisterInput true "User info"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /register [post]
func (h *Handler) RegisterHandler(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), 14)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password hashing failed"})
		return
	}

	_, err = h.DB.Exec(`
		INSERT INTO auth_schema.users (username, email, password_hash, role)
		VALUES ($1, $2, $3, $4)`,
		input.Username, input.Email, string(hash), input.Role)

	if err != nil {
		h.logger.Fatal("Insert error:", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register", "details": err.Error()})
		return
	}

	h.logger.Info("User registered")
	c.JSON(http.StatusOK, gin.H{"message": "registered"})
}

// LoginHandler логинит пользователя и возвращает токены
// @Summary Login user
// @Tags auth
// @Accept json
// @Produce json
// @Param input body LoginInput true "Login credentials"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /login [post]
func (h *Handler) LoginHandler(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	var user User
	err := h.DB.Get(&user, "SELECT * FROM auth_schema.users WHERE email=$1", input.Email)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password))
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "wrong password"})
		return
	}

	accessToken, err := domain.GenerateAccessToken(user.ID, user.Username, user.Role)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}

	refreshToken := domain.GenerateRefreshToken()
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	_, err = h.DB.Exec("INSERT INTO auth_schema.refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
		user.ID, refreshToken, expiresAt)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store refresh token"})
		return
	}

	h.logger.Info("User authorized")
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// RefreshHandler обновляет access token и возвращает новый refresh token
// @Summary Обновить access и refresh токены
// @Description Принимает refresh_token, проверяет его, выдает новый access_token и refresh_token
// @Tags auth
// @Accept json
// @Produce json
// @Param input body RefreshRequest true "Тело запроса с refresh_token"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse "Некорректный ввод"
// @Failure 401 {object} ErrorResponse "Неверный или истёкший refresh токен"
// @Failure 500 {object} ErrorResponse "Ошибка сервера"
// @Router /api/refresh [post]
func (h *Handler) RefreshHandler(c *gin.Context) {
	var input RefreshRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	var userID int
	var expiresAt time.Time
	err := h.DB.QueryRow("SELECT user_id, expires_at FROM auth_schema.refresh_tokens WHERE token=$1", input.RefreshToken).
		Scan(&userID, &expiresAt)
	if err != nil || time.Now().After(expiresAt) {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	_, err = h.DB.Exec("DELETE FROM auth_schema.refresh_tokens WHERE token = $1", input.RefreshToken)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete old refresh token"})
		return
	}

	var username, role string
	err = h.DB.QueryRow("SELECT username, role FROM auth_schema.users WHERE id=$1", userID).Scan(&username, &role)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not fetch user"})
		return
	}

	accessToken, err := domain.GenerateAccessToken(userID, username, role)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate access token"})
		return
	}

	newRefreshToken := domain.GenerateRefreshToken()
	newExpiresAt := time.Now().Add(30 * 24 * time.Hour)

	_, err = h.DB.Exec(
		"INSERT INTO auth_schema.refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
		userID, newRefreshToken, newExpiresAt,
	)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store new refresh token"})
		return
	}

	h.logger.Info("Refreshed new token")
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

// ProfileHandler возвращает имя пользователя из токена
// @Summary Get profile info
// @Tags profile
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /profile [get]
// @Security BearerAuth
func (h *Handler) ProfileHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	token := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	claims, err := domain.ParseAccessToken(token)
	if err != nil {
		h.logger.Fatal("error", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	h.logger.Info("User parsed successful")
	c.JSON(http.StatusOK, gin.H{"username": claims.Username})
}
