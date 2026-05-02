package main

import (
	"fmt"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase-community/gotrue-go"
)

func main() {
	projectReference := os.Getenv("SUPABASE_PROJECT_REFERENCE")

	apiKey := os.Getenv("SUPABASE_API_KEY")

	email := os.Getenv("EMAIL")

	password := os.Getenv("PASSWORD")

	cli := gotrue.New(projectReference, apiKey)

	res, err := cli.SignInWithEmailPassword(email, password)
	if err != nil {
		panic(err)
	}

	log.Printf("res: %+v\n\n", res)

	secret := os.Getenv("SUPABASE_JWT_SECRET")

	if err := VerifyAccessToken(res.AccessToken, []byte(secret)); err != nil {
		panic("failed to verify access token. error: " + err.Error())
	}

	ac := cli.WithToken(res.AccessToken)

	user, err := ac.GetUser()
	if err != nil {
		panic(err)
	}

	log.Printf("user: %+v", user)
}

func VerifyAccessToken(
	str string,
	secret []byte,
) error {
	res, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}

		return secret, nil
	})
	if err != nil {
		return err
	}

	if !res.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}
