package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/badoux/checkmail"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	// env variables
	REGION      = "region"
	TABLE_NAME  = "accountsTableName"
	SIGNING_KEY = "signingKey"
	INDEX_NAME  = "emailIndexName"

	// jwt token variables
	ISSUER      = "MyIssuer"
	EXPIRE_TIME = time.Hour * 24 // 24 hours in nano seconds
)

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Account struct {
	Id       string
	Email    string
	Password []byte
	Name     string
}

type Token struct {
	AccessToken string `json:"accessToken"`
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

// returns account from db by email if exists
func getAccountFromDb(email string) (Account, events.APIGatewayProxyResponse) {
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

	// check if there is an error or no results
	if err != nil {
		return Account{}, errorOccurred(http.StatusInternalServerError,
			fmt.Errorf("error occurred while querying the db: %s", err.Error()),
		)
	} else if *queryResult.Count < int64(1) {
		return Account{}, errorOccurred(http.StatusUnauthorized,
			fmt.Errorf("account with email = '%s' is not found", email),
		)
	}

	// unmarshal the account from db result
	var account Account
	if dynamodbattribute.UnmarshalMap(queryResult.Items[0], &account) != nil {
		return Account{}, errorOccurred(http.StatusInternalServerError,
			fmt.Errorf("failed to retrieve account from db"),
		)
	}

	return account, events.APIGatewayProxyResponse{}
}

// returns whether password is valid to the account in db
func validateAccountPassword(account Account, password string) (bool, events.APIGatewayProxyResponse) {
	passwordInput := &kms.DecryptInput{
		CiphertextBlob: account.Password,
	}

	// decrypt the password with KMS key
	decryptedPassword, err := kmsClient.Decrypt(passwordInput)
	if err != nil {
		return false, errorOccurred(http.StatusInternalServerError, err)
	}

	// check if it's the same as in db
	if bytes.Equal(decryptedPassword.Plaintext, []byte(password)) {
		return true, events.APIGatewayProxyResponse{}
	} else {
		log.Println("password is incorrect")
		return false, errorOccurred(http.StatusUnauthorized)
	}
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

// returns generated JWT token
func generateJwtToken(account Account) (string, events.APIGatewayProxyResponse) {
	// should be passed outside as a parameter
	mySigningKey := []byte(os.Getenv(SIGNING_KEY))

	// Create the Claims
	expiryTime := time.Now().Add(EXPIRE_TIME).Unix()
	claims := &jwt.StandardClaims{
		ExpiresAt: expiryTime,
		Issuer:    ISSUER,
		Subject:   account.Id,
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedJwtToken, err := jwtToken.SignedString(mySigningKey)

	if err != nil {
		return "", errorOccurred(http.StatusInternalServerError,
			fmt.Errorf("failed to convert body to json: %s", err.Error()),
		)
	}

	return signedJwtToken, events.APIGatewayProxyResponse{}
}

func HandleRequest(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Println("received body: ", request.Body)

	// parse credentials JSON
	var credentials Credentials
	err := json.Unmarshal([]byte(request.Body), &credentials)
	if err != nil {
		return errorOccurred(http.StatusBadRequest,
			fmt.Errorf("failed to parse body: %s", err.Error()),
		), nil
	}

	// validate email
	err = checkmail.ValidateFormat(credentials.Email)
	if err != nil {
		return errorOccurred(http.StatusBadRequest,
			fmt.Errorf("email is invalid: %s", err.Error()),
		), nil
	}

	// get account from db
	account, response := getAccountFromDb(credentials.Email)
	if response.StatusCode != 0 && response.Body != "" {
		return response, nil
	}

	// validate account password
	if credentialsValid, response := validateAccountPassword(account, credentials.Password); !credentialsValid {
		return response, nil
	}

	// generate jwt token
	jwtToken, response := generateJwtToken(account)
	if response.StatusCode != 0 && response.Body != "" {
		return response, nil
	}

	// return JSON response
	jwtTokenJson, err := json.Marshal(map[string]string{
		"accessToken": "Bearer " + jwtToken,
	})
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(jwtTokenJson),
	}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
