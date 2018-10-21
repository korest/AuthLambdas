.PHONY: build
build:
	dep ensure -v
	env GOOS=linux go build -ldflags="-s -w" -o bin/authentication authentication/main.go
	env GOOS=linux go build -ldflags="-s -w" -o bin/authorization authorization/main.go
	env GOOS=linux go build -ldflags="-s -w" -o bin/registration registration/main.go

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	rm -rf ./bin ./vendor Gopkg.lock

.PHONY: deploy
deploy: clean build test
	sls deploy --verbose
