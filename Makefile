GO_BINARY=hvresult

.PHONY: all build test clean generate lint run

all: build test

build:
	go build -o $(GO_BINARY) .

test:
	go test -v ./...

clean:
	rm -f $(GO_BINARY)

generate:
	go generate ./...

lint:
	golangci-lint run ./...

run:
	./$(GO_BINARY) --help
