GOPATH := $(shell go env GOPATH)


format:
	go fmt ./...

test:
	go test -cover ./... -coverprofile=cover.out

lint:
	${GOPATH}/bin/staticcheck ./...

.PHONY: format test lint
