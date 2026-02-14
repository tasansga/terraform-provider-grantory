DIST_DIR=dist

$(info $(shell mkdir -p $(DIST_DIR)))

default: all

all: lint build test clean

build:
	go build -o "${DIST_DIR}/terraform-provider-grantory" cmd/terraform-provider-grantory/main.go
	go build -o "${DIST_DIR}/grantory" cmd/grantory/main.go

lint:
	#tfproviderlint -R001=false ./...
	golangci-lint run ./cmd/terraform-provider-grantory
	golangci-lint run ./cmd/grantory
	golangci-lint run ./internal/...

modupdate:
	go get -u ./...
	go mod tidy

tidy:
	go mod tidy

doc:
	rm -Rf "$(shell git rev-parse --show-toplevel)/docs" \
	&& tfplugindocs generate \
	  --provider-dir cmd/terraform-provider-grantory \
	  --provider-name grantory \
	  --rendered-website-dir docs \
	&& mv cmd/terraform-provider-grantory/docs "$(shell git rev-parse --show-toplevel)"

test: build unittest

unittest:
	go test -v ./internal/...

clean:
	go clean
	go mod tidy
	rm -f "${DIST_DIR}/terraform-provider-grantory"
	rm -Rf ./docs

.PHONY: all build lint modupdate tidy doc test unittest clean
