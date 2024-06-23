package util

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type UserClaim struct {
	Id       int
	Identity string
	Name     string
	jwt.StandardClaims
}

var JwtKey = "cloud-disk-key"

// GenerateToken 生成token
func GenerateToken(id int, identity, name string, second int) (string, error) {
	uc := UserClaim{
		Id:       id,
		Identity: identity,
		Name:     name,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * time.Duration(second)).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, uc)
	tokenString, err := token.SignedString([]byte(JwtKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ParseToken 解析token
func ParseToken(tokenString string) (*UserClaim, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaim{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(JwtKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserClaim); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}
