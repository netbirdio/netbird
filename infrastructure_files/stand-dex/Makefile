## NetBird Device Certificate Auth — Development Stand
## =====================================================
##
## Prerequisites:
##   - Docker + Docker Compose v2
##   - netbird CLI (for full E2E: netbird up/down)
##
## Quick start:
##   make build   # build custom management + dashboard images
##   make up      # start the stand
##   make e2e     # run automated E2E tests
##   make down    # stop and clean up

REPO_ROOT    := $(shell cd ../.. && pwd)
DASHBOARD_REPO ?= $(REPO_ROOT)/../netbird-dashboard

MGMT_IMAGE   := netbird/management:tpm-dev
DASH_IMAGE   := netbird/dashboard:tpm-dev

# PAT token pre-generated with correct checksum (see docker-compose.device-auth.yml)
DEV_TOKEN    := nbp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd34KlM6
API_URL      := https://localhost
# Direct management TLS port for mTLS testing (bypasses Caddy, see docker-compose.device-auth.yml)
GRPC_URL     := https://localhost:8443

COMPOSE      := docker compose -f docker-compose.yml -f docker-compose.device-auth.yml

.PHONY: help build build-mgmt build-dashboard up down restart logs wait e2e e2e-verbose get-setup-key clean status token

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

## ─── Image Builds ────────────────────────────────────────────────────────────

build: build-mgmt build-dashboard ## Build both management and dashboard images

build-mgmt: ## Build management image from current branch
	@echo "Building management image $(MGMT_IMAGE)..."
	docker build \
		--no-cache \
		-f $(REPO_ROOT)/management/Dockerfile.multistage \
		-t $(MGMT_IMAGE) \
		$(REPO_ROOT)

build-dashboard: ## Build dashboard image from current branch
	@echo "Building dashboard image $(DASH_IMAGE)..."
	@if [ ! -d "$(DASHBOARD_REPO)" ]; then \
		echo "ERROR: Dashboard repo not found at $(DASHBOARD_REPO)"; \
		echo "Set DASHBOARD_REPO=<path> or clone netbird-dashboard next to netbird"; \
		exit 1; \
	fi
	cd $(DASHBOARD_REPO) && docker build -t $(DASH_IMAGE) .

## ─── Stand Lifecycle ─────────────────────────────────────────────────────────

up: ## Start the stand (pulls/uses images, starts all services)
	$(COMPOSE) up -d
	@echo ""
	@echo "Stand starting... run 'make wait' to wait until ready"
	@echo "UI:  https://localhost  (admin@netbird.localhost / Netbird@dev1)"
	@echo "API: Bearer $(DEV_TOKEN)"

wait: ## Wait until management API is healthy
	@echo "Waiting for management API..."
	@for i in $$(seq 1 30); do \
		if curl -sk https://localhost/api/device-auth/settings \
			-H "Authorization: Bearer $(DEV_TOKEN)" \
			-o /dev/null -w '%{http_code}' | grep -qE '^[24]'; then \
			echo "Management API is ready!"; \
			exit 0; \
		fi; \
		echo "  attempt $$i/30..."; \
		sleep 3; \
	done; \
	echo "ERROR: Management API not ready after 90s"; \
	exit 1

down: ## Stop the stand and remove containers
	$(COMPOSE) down

clean: ## Stop and remove containers AND volumes (destroys all data)
	$(COMPOSE) down -v

restart: ## Restart the management container (after rebuilding image)
	$(COMPOSE) restart management

logs: ## Tail management logs
	$(COMPOSE) logs -f management

## ─── E2E Tests ───────────────────────────────────────────────────────────────

get-setup-key: ## Print the setup key created by dev-stand-init
	@docker compose -f docker-compose.yml -f docker-compose.device-auth.yml \
		exec management sh -c 'grep NETBIRD_SETUP_KEY /var/lib/netbird/init.env 2>/dev/null | cut -d= -f2 || echo ""'

e2e: ## Run automated device certificate auth E2E tests
	@echo "Running E2E tests against $(API_URL)..."
	@SETUP_KEY=$$(docker compose -f docker-compose.yml -f docker-compose.device-auth.yml \
		exec -T management sh -c 'grep NETBIRD_SETUP_KEY /var/lib/netbird/init.env 2>/dev/null | cut -d= -f2' 2>/dev/null); \
	if [ -z "$$SETUP_KEY" ]; then \
		echo "WARN: NETBIRD_SETUP_KEY not found, enrollment tests will be skipped"; \
	fi; \
	NETBIRD_TEST_TOKEN=$(DEV_TOKEN) \
	NETBIRD_API_URL=$(API_URL) \
	NETBIRD_GRPC_URL=$(GRPC_URL) \
	NETBIRD_SETUP_KEY="$$SETUP_KEY" \
		../../scripts/e2e-device-auth.sh

e2e-verbose: ## Run E2E tests with verbose curl output
	@echo "Running E2E tests (verbose) against $(API_URL)..."
	NETBIRD_TEST_TOKEN=$(DEV_TOKEN) \
	NETBIRD_API_URL=$(API_URL) \
	NETBIRD_GRPC_URL=$(GRPC_URL) \
	NETBIRD_E2E_VERBOSE=1 \
		../../scripts/e2e-device-auth.sh

## ─── Development Helpers ─────────────────────────────────────────────────────

ui: ## Open the dashboard in default browser
	open https://localhost 2>/dev/null || xdg-open https://localhost

status: ## Show device auth settings from API
	@curl -sk -H "Authorization: Bearer $(DEV_TOKEN)" $(API_URL)/api/device-auth/settings | python3 -m json.tool

token: ## Print the dev admin token
	@echo $(DEV_TOKEN)
