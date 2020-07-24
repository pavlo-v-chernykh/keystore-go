fmt:
	go fmt github.com/pavel-v-chernykh/keystore-go/v3/...

lint:
	golangci-lint run -c .golangci.yaml

test:
	go test -cover -count=1 -v ./...

all: fmt lint test

.PHONY: fmt lint test all
.DEFAULT_GOAL := all
