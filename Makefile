BINARY := tmt

.PHONY: build test fmt
build:
	go build -o $(BINARY) .

test:
	go test ./...

fmt:
	gofmt -l -w .
