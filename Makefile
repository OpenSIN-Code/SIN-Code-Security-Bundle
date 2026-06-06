.PHONY: all build build-all test clean install lint fmt setup scan-openafd

GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_NAME=sin-security
BINARY_DIR=bin
PYTHON=python3
PIP=pip
VENV=venv

all: build

## Build Go CLI
build:
	@echo "🔨 Building Go CLI..."
	mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME) ./cmd/sin-security
	@echo "✅ Built: $(BINARY_DIR)/$(BINARY_NAME)"

## Build for all platforms
build-all:
	@echo "🔨 Building for all platforms..."
	mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/sin-security
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/sin-security
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/sin-security
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/sin-security
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/sin-security
	@echo "✅ Built all platforms"

## Run tests
test: test-go test-python

test-go:
	@echo "🧪 Running Go tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

test-python:
	@echo "🧪 Running Python tests..."
	. $(VENV)/bin/activate && pytest tests/ -v

## Install dependencies
deps: deps-go deps-python

deps-go:
	@echo "📦 Installing Go dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

deps-python:
	@echo "📦 Installing Python dependencies..."
	$(PYTHON) -m venv $(VENV)
	. $(VENV)/bin/activate && $(PIP) install -r requirements.txt

## Install CLI globally
install: build
	@echo "📥 Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BINARY_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "✅ Installed"

## Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	rm -rf $(BINARY_DIR)
	rm -f coverage.out
	rm -rf $(VENV)
	rm -rf __pycache__
	rm -rf .pytest_cache
	find . -name "*.pyc" -delete
	@echo "✅ Cleaned"

## Scan OpenAfD-Chat (your AnythingLLM-based project)
scan-openafd:
	@echo "🇩🇪 Scanning OpenAfD-Chat..."
	./$(BINARY_DIR)/$(BINARY_NAME) openafd ../OpenAfD-Chat \
		--url http://localhost:3001

## Generate executive summary
executive-report:
	@echo "📊 Generating executive report..."
	./$(BINARY_DIR)/$(BINARY_NAME) scan . --compliance cis,nist,soc2 --format json > executive-report.json
	@echo "✅ Report saved to executive-report.json"

## Generate HTML dashboard
dashboard:
	@echo "📈 Generating HTML dashboard..."
	. $(VENV)/bin/activate && python -c "\
from src.tools.bundle_scanner import BundleScanner; \
from src.tools.compliance_dashboard import ComplianceDashboard; \
s = BundleScanner(); r = s.full_scan('.'); \
d = ComplianceDashboard(); h = d.generate_html_dashboard(r); \
d.save_report(h, 'dashboard.html')"
	@echo "✅ Dashboard saved to dashboard.html"

## Lint code
lint: lint-go lint-python

lint-go:
	@echo "🔍 Linting Go code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "⚠️  golangci-lint not installed"; \
	fi

lint-python:
	@echo "🔍 Linting Python code..."
	. $(VENV)/bin/activate && ruff check src/ tests/

## Format code
fmt: fmt-go fmt-python

fmt-go:
	@echo "🎨 Formatting Go code..."
	$(GOCMD) fmt ./...

fmt-python:
	@echo "🎨 Formatting Python code..."
	. $(VENV)/bin/activate && black src/ tests/

## Full setup
setup: deps build
	@echo "✅ Setup complete!"

## Show help
help:
	@echo "🎯 SIN-Code Security Bundle - Makefile Commands"
	@echo ""
	@echo "Build:"
	@echo "  make build             - Build Go CLI"
	@echo "  make build-all         - Build for all platforms"
	@echo "  make install           - Install CLI globally"
	@echo ""
	@echo "Scanning:"
	@echo "  make scan-openafd      - Scan OpenAfD-Chat (AnythingLLM)"
	@echo "  make executive-report  - Generate executive report"
	@echo "  make dashboard         - Generate HTML dashboard"
	@echo ""
	@echo "Development:"
	@echo "  make deps              - Install all dependencies"
	@echo "  make test              - Run all tests"
	@echo "  make lint              - Lint code"
	@echo "  make fmt               - Format code"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean             - Clean build artifacts"
	@echo "  make setup             - Full setup"
