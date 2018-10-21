package main

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"
)

const (
	TEST_EXISTING_EMAIL     = "orest@test.com"
	TEST_NOT_EXISTING_EMAIL = "test@test.com"
	TEST_PASSWORD           = "password"
)

type MockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
}

type MockKMS struct {
	kmsiface.KMSAPI
}

// if we pass existing email we get the result
// else if we pass not existing email we get empty result
// else we return db error
func (mockDynamoDb *MockDynamoDB) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	email := *input.KeyConditions["email"].AttributeValueList[0].S
	if email == TEST_EXISTING_EMAIL {
		count := int64(1)
		return &dynamodb.QueryOutput{
			Items: []map[string]*dynamodb.AttributeValue{
				{
					"email": {
						S: aws.String(TEST_EXISTING_EMAIL),
					},
					"password": {
						B: []byte(TEST_PASSWORD),
					},
				},
			},
			Count: &count,
		}, nil
	} else if email == TEST_NOT_EXISTING_EMAIL {
		count := int64(0)
		return &dynamodb.QueryOutput{
			Count: &count,
		}, nil
	} else {
		return nil, fmt.Errorf("test error")
	}
}

func (mockKms *MockKMS) Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	return &kms.DecryptOutput{
		Plaintext: input.CiphertextBlob,
	}, nil
}

func init() {
	ddbClient = &MockDynamoDB{}
	kmsClient = &MockKMS{}

	os.Setenv(REGION, "us-west-2")
	os.Setenv(SIGNING_KEY, "my signing key")
	os.Setenv(TABLE_NAME, "test table")
}

func TestGetExistingAccountFromDb(t *testing.T) {
	account, _ := getAccountFromDb(TEST_EXISTING_EMAIL)

	assert.Equal(t, TEST_EXISTING_EMAIL, account.Email)
	assert.Equal(t, []byte(TEST_PASSWORD), account.Password)
}

func TestGetNotExistingAccountFromDb(t *testing.T) {
	_, response := getAccountFromDb(TEST_NOT_EXISTING_EMAIL)

	assert.NotNil(t, response)
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
}

func TestGetAccountFromDbWithError(t *testing.T) {
	_, response := getAccountFromDb("any@test.com")

	assert.NotNil(t, response)
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
}

func TestValidateAccountPassword(t *testing.T) {
	account, _ := getAccountFromDb(TEST_EXISTING_EMAIL)
	valid, _ := validateAccountPassword(account, TEST_PASSWORD)

	assert.True(t, valid)
}

func TestValidateAccountInvalidPassword(t *testing.T) {
	account, _ := getAccountFromDb(TEST_EXISTING_EMAIL)
	invalid, response := validateAccountPassword(account, "invalid_password")

	assert.False(t, invalid)
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
}

func TestGenerateJwtToken(t *testing.T) {
	accountId := "AccountId"
	testPassword := []byte(TEST_PASSWORD)
	account := Account{Id: accountId, Email: TEST_EXISTING_EMAIL, Password: testPassword, Name: "Account name"}

	jwtToken, response := generateJwtToken(account)
	assert.Equal(t, 0, response.StatusCode) // default
	assert.Equal(t, "", response.Body)      // default

	assert.True(t, len(jwtToken) > 0)

	token, _ := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			assert.Fail(t, "wrong signing method")
		}

		signingKey := []byte(os.Getenv(SIGNING_KEY))
		return signingKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		claimsMap := map[string]interface{}(claims)
		assert.Equal(t, accountId, claimsMap["sub"].(string))
		assert.True(t, claims.VerifyIssuer(ISSUER, true))
		assert.Equal(t, nil, claims.Valid())
	} else {
		assert.Fail(t, "token is invalid")
	}
}

func TestHandleRequestValidCredentials(t *testing.T) {
	body, _ := json.Marshal(Credentials{
		Email:    TEST_EXISTING_EMAIL,
		Password: TEST_PASSWORD,
	})
	request := events.APIGatewayProxyRequest{Body: string(body)}

	response, err := HandleRequest(request)
	assert.Nil(t, err)
	assert.NotNil(t, response)

	var token Token
	json.Unmarshal([]byte(response.Body), &token)

	assert.NotNil(t, token.AccessToken)
}

func TestHandleRequestNotValidEmail(t *testing.T) {
	body, _ := json.Marshal(Credentials{
		Email:    "not valid email",
		Password: TEST_PASSWORD,
	})
	request := events.APIGatewayProxyRequest{Body: string(body)}

	response, err := HandleRequest(request)
	assert.Nil(t, err)
	assert.NotNil(t, response)

	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
}

func TestHandleRequestNotValidBody(t *testing.T) {
	request := events.APIGatewayProxyRequest{Body: "random string"}

	response, err := HandleRequest(request)
	assert.Nil(t, err)
	assert.NotNil(t, response)

	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
}
