.PHONY: all build test test-race vet fmt lint playwright-install playwright-check clean

all: build

build:
	go build -o tbank-capture ./cmd/tbank-capture

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	test -z "$$(gofmt -l .)"

playwright-install:
	./scripts/install-playwright.sh

playwright-check:
	./scripts/install-playwright.sh --check

clean:
	rm -f tbank-capture
