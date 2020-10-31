fmt:
	go fmt github.com/pavel-v-chernykh/keystore-go/v4/...

lint:
	golangci-lint run -c .golangci.yaml

lint-examples:
	cd examples/compare && golangci-lint run -c ../../.golangci.yaml
	cd examples/keypass && golangci-lint run -c ../../.golangci.yaml
	cd examples/pem && golangci-lint run -c ../../.golangci.yaml
	cd examples/truststore && golangci-lint run -c ../../.golangci.yaml

run-examples:
	cd examples/compare && go run main.go
	cd examples/keypass && go run main.go
	cd examples/pem && go run main.go
	cd examples/truststore && go run main.go "/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/jre/lib/security/cacerts" "changeit"

test:
	go test -cover -count=1 -v ./...

test-coverprofile:
	go test -coverprofile=coverage.out -cover -count=1 -v ./...

cover:
	go tool cover -html=coverage.out

all: fmt lint test

.PHONY: fmt lint test all
.DEFAULT_GOAL := all
