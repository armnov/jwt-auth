package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

var JWT_SECRET = []byte("secret_sekali")
var TOKEN_DURATION = 60 * time.Second
var token string

type MyClaims struct {
	username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	fmt.Println("App started...")
	fmt.Println("Generating tokens")

	//defer validateToken(token)
	token = generateToken()
	fmt.Println(token)
	validateToken(token)

	fmt.Println("====== with claims ======")

	tokenWithClaims := generateTokenWithClaims()
	validateTokenWithClaims(tokenWithClaims)

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

func generateTokenWithClaims() string {

	//create claims
	claims := MyClaims{
		"admin",
		jwt.StandardClaims{
			ExpiresAt: time.Now().UTC().Add(TOKEN_DURATION).Unix(),
			Issuer:    "MY_APP",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(JWT_SECRET)

	if err != nil {
		fmt.Println("Error generating token with claims: ", err.Error())
	}

	fmt.Println("Token with claims generated: ", ss)

	return ss
}

func validateTokenWithClaims(t string) {
	token, err := jwt.ParseWithClaims(t, &MyClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWT_SECRET), nil
	})

	if err != nil {
		fmt.Println("Error parsing token: ", err.Error())
	}

	if claims, ok := token.Claims.(*MyClaims); ok && token.Valid {
		fmt.Println("Claims valid: ", claims.username, claims.StandardClaims.ExpiresAt, claims.Issuer)
	} else {
		fmt.Println("Somethign is wrong with the claims")
	}

}
