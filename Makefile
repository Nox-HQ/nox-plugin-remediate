PLUGIN_NAME := nox-plugin-remediate

.PHONY: build test

build:
	go build -o $(PLUGIN_NAME) .

test:
	go test ./...
