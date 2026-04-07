package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
)

// jwtSecret is generated at startup
var jwtSecret []byte

func init() {
	jwtSecret = make([]byte, 32)
	rand.Read(jwtSecret)
}

// SetSecret allows setting a persistent JWT secret
func SetSecret(secret string) {
	jwtSecret = []byte(secret)
}

// HashPassword creates a bcrypt hash
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword verifies a password against a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Claims for JWT
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateToken creates a JWT token
func GenerateToken(userID uint, username string) (string, error) {
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateToken parses and validates a JWT token
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// GenerateRandomString creates a random hex string
func GenerateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

// GenerateRandomPort generates a random port between 10000-60000
func GenerateRandomPort() int {
	b := make([]byte, 2)
	rand.Read(b)
	port := int(b[0])<<8 | int(b[1])
	return 10000 + (port % 50000)
}
