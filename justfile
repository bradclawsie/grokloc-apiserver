set shell := ["fish", "-c"]
set dotenv-load

default:
    @just --list

build:
    go build ./...

mod:
    go get -u ./...
    go mod tidy
    go mod download
    go mod vendor
    go build ./...

test:
    go test -race -v ./...

lint:
    golangci-lint --timeout=24h run pkg/... && staticcheck ./... && go vet ./... && govulncheck ./...

psql:
    psql $POSTGRES_APP_URL

truncate:
    psql $POSTGRES_APP_URL -c "truncate users"
    psql $POSTGRES_APP_URL -c "truncate orgs"
    psql $POSTGRES_APP_URL -c "truncate repositories"
    psql $POSTGRES_APP_URL -c "truncate audit"

tools:
    go install golang.org/x/tools/cmd/goimports@latest
    go install mvdan.cc/gofumpt@latest
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    go install honnef.co/go/tools/cmd/staticcheck@latest
    go install golang.org/x/vuln/cmd/govulncheck@latest
    go install golang.org/x/tools/gopls@latest

ci: mod test lint
