VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMPOSE  = docker compose -f deploy/compose/docker-compose.yml

.PHONY: build run test vet fmt tidy docker demo-up demo-down demo-logs

build:
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/patchline ./cmd/patchline

run: build
	./bin/patchline

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

docker:
	docker build --build-arg VERSION=$(VERSION) -t patchline:$(VERSION) .

demo-up:
	$(COMPOSE) up -d --build

demo-down:
	$(COMPOSE) down

demo-logs:
	$(COMPOSE) logs -f patchline
