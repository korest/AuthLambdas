package main

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func init() {
	os.Setenv(SIGNING_KEY, "my signing key")
}

func TestHandleRequestValidToken(t *testing.T) {
	response, err := HandleRequest(nil, events.APIGatewayCustomAuthorizerRequest{
		AuthorizationToken: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1Mzg0MzYwNjYxMTUsImlzcyI6Ik15SXNzdWVyIiwic3ViIjoiQWNjb3VudElkIn0.Em7K73Gfr2YfB3heEk2ugxty24-GAjMRUgxgun3ORKE",
		MethodArn:          "MethodArn",
	})

	assert.Nil(t, err)
	assert.Equal(t, ALLOW, response.PolicyDocument.Statement[0].Effect)
	assert.Equal(t, "AccountId", response.PrincipalID)
}
