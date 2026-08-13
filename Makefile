BINARY := tmt
LAMBDA_ZIP := internal/jump/lambdafn.zip

.PHONY: build test fmt lambda clean

# lambda compiles the jump-host function for AWS (Graviton/arm64, provided
# runtime) and zips it as `bootstrap`, which internal/jump embeds. It must run
# before any `go build`/`go test` because the //go:embed needs the zip present.
lambda: $(LAMBDA_ZIP)

$(LAMBDA_ZIP): cmd/lambdafn/main.go internal/wire/wire.go
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bootstrap ./cmd/lambdafn
	zip -j $(LAMBDA_ZIP) bootstrap
	rm -f bootstrap

build: lambda
	go build -o $(BINARY) .

test: lambda
	go test ./...

fmt:
	gofmt -l -w .

clean:
	rm -f $(BINARY) bootstrap $(LAMBDA_ZIP)
