package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

var JWT_SECRET = []byte("secret_sekali")
var TOKEN_DURATION = 60 * time.Second
var token string

func main() {
	fmt.Println("App started...")
	fmt.Println("Generating tokens")

	//defer validateToken(token)
	token = generateToken()
	fmt.Println(token)
	validateToken(token)

}

func generateToken() string {

	//generate token with standard claims
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().UTC().Add(TOKEN_DURATION).Unix(),
		Issuer:    "my app",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(JWT_SECRET)

	if err != nil {
		fmt.Println("Error when generating token")
	}

	return signedToken

}

func validateToken(t string) {

	//parse token string
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		//return secret
		return JWT_SECRET, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["exp"], claims["iss"])
	} else {
		fmt.Println("Error when parsing token: ", err.Error())
	}
}
