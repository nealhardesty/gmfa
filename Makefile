# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test

CGO_ENABLED=1 
# $env:CGO_ENABLED=1; go run demo.go

build:
	$(GOBUILD)

run: build
	go run .

clean:
	$(GOCLEAN)

# Initial init
init:
	$(GOMOD) init github.com/nealhardesty/gmfa

# Update Go modules
mod:
	$(GOMOD) tidy
	$(GOMOD) vendor

# Run tests
test:
	$(GOTEST) -v ./...

.PHONY: build run clean mod test
