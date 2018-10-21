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
						S: aws.String(TEST_PASSWORD),
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

func (mockDynamoDb *MockDynamoDB) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	email := *input.Item["email"].S
	if email == TEST_NOT_EXISTING_EMAIL {
		return &dynamodb.PutItemOutput{}, nil
	} else {
		return nil, fmt.Errorf("error occurred while saving to db")
	}
}

func (mockKms *MockKMS) Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error) {
	return &kms.EncryptOutput{
		CiphertextBlob: input.Plaintext,
	}, nil
}

func init() {
	ddbClient = &MockDynamoDB{}
	kmsClient = &MockKMS{}

	os.Setenv(REGION, "us-west-2")
	os.Setenv(TABLE_NAME, "test table")
}

func TestCheckIfAccountInNew(t *testing.T) {
	isNew, _ := checkIfAccountInNew(TEST_NOT_EXISTING_EMAIL)
	assert.True(t, isNew)
}

func TestCheckIfAccountIsNotNew(t *testing.T) {
	isNew, response := checkIfAccountInNew(TEST_EXISTING_EMAIL)
	assert.False(t, isNew)
	assert.Equal(t, http.StatusConflict, response.StatusCode)
}

func TestEncryptPassword(t *testing.T) {
	encryptedPassword, _ := encryptPassword(TEST_PASSWORD)

	assert.Equal(t, TEST_PASSWORD, string(encryptedPassword))
}

func TestCreateAccountInDb(t *testing.T) {
	created, _ := createAccountInDb(Account{
		Name:     "Test account",
		Email:    TEST_NOT_EXISTING_EMAIL,
		Password: TEST_PASSWORD,
	})

	assert.True(t, created)
}

func TestCreateAccountInDbFailed(t *testing.T) {
	created, response := createAccountInDb(Account{
		Name:     "Test account",
		Email:    TEST_EXISTING_EMAIL,
		Password: TEST_PASSWORD,
	})

	assert.False(t, created)
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
}

func TestHandleRequest(t *testing.T) {
	body, _ := json.Marshal(Account{
		Email:    TEST_NOT_EXISTING_EMAIL,
		Password: TEST_PASSWORD,
		Name:     "Test name",
	})
	request := events.APIGatewayProxyRequest{Body: string(body)}
	response, _ := HandleRequest(request)

	assert.Equal(t, http.StatusOK, response.StatusCode)
}
