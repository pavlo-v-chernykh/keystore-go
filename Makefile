.PHONY: fmt
fmt:
	go fmt github.com/pavlo-v-chernykh/keystore-go/v4/...

.PHONY: lint
lint:
	golangci-lint run -c .golangci.yaml

.PHONY: lint-examples
lint-examples:
	cd examples/compare && golangci-lint run -c ../../.golangci.yaml
	cd examples/keypass && golangci-lint run -c ../../.golangci.yaml
	cd examples/pem && golangci-lint run -c ../../.golangci.yaml
	cd examples/truststore && golangci-lint run -c ../../.golangci.yaml

.PHONY: run-examples
run-examples:
	cd examples/compare && go run main.go
	cd examples/keypass && go run main.go
	cd examples/pem && go run main.go
	cd examples/truststore && go run main.go "$(shell /usr/libexec/java_home)/lib/security/cacerts" "changeit"

.PHONY: test
test:
	go test -cover -count=1 -v ./...

.PHONY: test-coverprofile
test-coverprofile:
	go test -coverprofile=coverage.out -cover -count=1 -v ./...

.PHONY: cover
cover:
	go tool cover -html=coverage.out

.PHONY: all
all: fmt lint test

.DEFAULT_GOAL := all
