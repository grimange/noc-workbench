.PHONY: check test integration build run up db-up db-down
check:
	@test -z "$$(gofmt -l cmd internal)" || (echo 'Run gofmt on Go sources'; exit 1)
	go vet ./...
	go test ./...
	go build ./...
test:
	go test ./...
integration:
	@test -n "$$NOC_TEST_DATABASE_URL" || (echo 'Set NOC_TEST_DATABASE_URL to an isolated loopback test DB'; exit 1)
	go test -count=1 -v ./internal/store/postgres
build:
	go build -o /tmp/noc-workbench ./cmd/noc-workbench
run:
	go run ./cmd/noc-workbench
up: db-up run
db-up:
	docker compose -f deployments/compose.yaml up -d --wait
db-down:
	docker compose -f deployments/compose.yaml down
