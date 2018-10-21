package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/dgrijalva/jwt-go"
	"log"
	"os"
	"strings"
)

const (
	// env variables
	SIGNING_KEY = "signingKey"
	ALLOW       = "allow"
)

func createPolicy(accountId, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: accountId,
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		},
	}
}

func HandleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Println("token received: ", event.AuthorizationToken)

	tokenStr := strings.TrimPrefix(event.AuthorizationToken, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("wrong signing method")
		}

		signingKey := []byte(os.Getenv(SIGNING_KEY))
		return signingKey, nil
	})

	if err == nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			log.Println("token claims: ", claims)
			accountId := claims["sub"].(string)
			err = claims.Valid()
			if err == nil {
				return createPolicy(accountId, ALLOW, event.MethodArn), nil
			}
		}
	}

	log.Println("token invalid: ", err.Error())

	return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
}

func main() {
	lambda.Start(HandleRequest)
}
