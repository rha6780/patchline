VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMPOSE  = docker compose -f deploy/compose/docker-compose.yml
SELF     = docker compose --project-directory deploy/self-hosted -f deploy/self-hosted/docker-compose.yml

.PHONY: build run test vet fmt tidy docker demo-up demo-seed demo-seed-dt demo-down demo-logs up down logs

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

# Demo: Patchline + Trivy; PROFILE=dependency-track adds Dependency-Track.
demo-up:
	$(COMPOSE) $(foreach p,$(PROFILE),--profile $(p)) up -d --build

# Uploads the sample SBOMs to Patchline (needs curl, jq).
demo-seed:
	sh deploy/compose/seed.sh

# Wires Dependency-Track to Patchline and uploads the sample SBOM there.
demo-seed-dt:
	sh deploy/compose/seed.sh dt

demo-down:
	$(COMPOSE) --profile dependency-track down

demo-logs:
	$(COMPOSE) logs -f patchline

# Self-hosted (deploy/self-hosted/.env); PROFILE="dependency-track trivy" adds those services.
up:
	$(SELF) $(foreach p,$(PROFILE),--profile $(p)) up -d --build

down:
	$(SELF) $(foreach p,$(PROFILE),--profile $(p)) down

logs:
	$(SELF) logs -f patchline
