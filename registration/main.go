package main

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/satori/go.uuid"
	"log"
	"net/http"
	"os"
)

const (
	KMS_KEY    = "kmsKey"
	TABLE_NAME = "accountsTableName"
	INDEX_NAME = "emailIndexName"
	REGION     = "region"
)

type Account struct {
	Id       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

var ddbClient dynamodbiface.DynamoDBAPI
var kmsClient kmsiface.KMSAPI

// init DynamoDb
func init() {
	region := os.Getenv(REGION)
	awsSession, err := session.NewSession(&aws.Config{
		Region: &region,
	})

	if err != nil {
		log.Println(fmt.Sprintf("Failed to create new AWS session: %s", err.Error()))
	} else {
		ddbClient = dynamodbiface.DynamoDBAPI(dynamodb.New(awsSession))
		kmsClient = kmsiface.KMSAPI(kms.New(awsSession))
	}
}

// returns true if account doesn't exist in db
func checkIfAccountInNew(email string) (bool, events.APIGatewayProxyResponse) {
	// db query
	input := &dynamodb.QueryInput{
		TableName: aws.String(os.Getenv(TABLE_NAME)),
		IndexName: aws.String(os.Getenv(INDEX_NAME)),
		KeyConditions: map[string]*dynamodb.Condition{
			"email": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String(email),
					},
				},
			},
		},
	}

	queryResult, err := ddbClient.Query(input)

	// check if there is an error
	if err != nil {
		return false, errorOccurred(http.StatusInternalServerError,
			fmt.Errorf("error occurred while querying the db: %s", err.Error()),
		)
	}

	if *queryResult.Count > int64(0) {
		return false, errorOccurred(http.StatusConflict,
			fmt.Errorf("account with email = '%s' already exists", email),
		)
	}

	return true, events.APIGatewayProxyResponse{}
}

// returns encrypted password
func encryptPassword(password string) ([]byte, events.APIGatewayProxyResponse) {
	passwordInput := &kms.EncryptInput{
		KeyId:     aws.String(os.Getenv(KMS_KEY)),
		Plaintext: []byte(password),
	}

	// encrypt the password with KMS key
	encryptedPassword, err := kmsClient.Encrypt(passwordInput)
	if err != nil {
		return nil, errorOccurred(http.StatusInternalServerError, err)
	}

	return encryptedPassword.CiphertextBlob, events.APIGatewayProxyResponse{}
}

// creates account in db
func createAccountInDb(account Account) (bool, events.APIGatewayProxyResponse) {
	encryptedPassword, response := encryptPassword(account.Password)
	if response.StatusCode != 0 && response.Body != "" {
		return false, response
	}

	id := uuid.NewV4().String()[0:8]
	input := &dynamodb.PutItemInput{
		TableName: aws.String(os.Getenv(TABLE_NAME)),
		Item: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
			"email": {
				S: aws.String(account.Email),
			},
			"password": {
				B: encryptedPassword,
			},
			"name": {
				S: aws.String(account.Name),
			},
		},
	}

	if _, err := ddbClient.PutItem(input); err != nil {
		return false, errorOccurred(http.StatusInternalServerError,
			fmt.Errorf("error occurred while querying the db: %s", err.Error()),
		)
	}

	return true, events.APIGatewayProxyResponse{}
}

// returns API response with specific statusCode and error message as a body
func errorOccurred(statusCode int, errors ...error) events.APIGatewayProxyResponse {
	for _, err := range errors {
		log.Println(err.Error())
	}

	body, _ := json.Marshal(map[string]string{
		"errorMessage": http.StatusText(statusCode),
	})

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Body:       string(body),
	}
}

func HandleRequest(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Println("received body: ", request.Body)

	// parse account JSON
	var account Account
	err := json.Unmarshal([]byte(request.Body), &account)
	if err != nil {
		return errorOccurred(http.StatusBadRequest,
			fmt.Errorf("failed to parse body: %s", err.Error()),
		), nil
	}

	// check if account doesn't exist in db
	if isNew, response := checkIfAccountInNew(account.Email); !isNew {
		return response, nil
	}

	// create account in db
	if created, response := createAccountInDb(account); !created {
		return response, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       "",
	}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
