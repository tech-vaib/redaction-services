# Makefile — All development, test, and deployment commands
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   make setup        → Install deps and download spaCy model
#   make test         → Run all tests (unit + integration)
#   make test-unit    → Unit tests only (fast)
#   make test-acc     → Accuracy tests (requires faker)
#   make test-load    → Load test (requires locust + running server)
#   make dev          → Start local dev server
#   make docker-build → Build Docker image
#   make docker-run   → Run Docker image locally
#   make compose-up   → Start full stack (+ Prometheus/Grafana)
#   make deploy-aks   → Deploy to AKS
# ─────────────────────────────────────────────────────────────────────────────

PYTHON     := python3
PIP        := pip3
IMAGE_NAME := pii-redaction
IMAGE_TAG  := 2.0.0
ACR_NAME   := YOUR_ACR
NAMESPACE  := redaction
HELM_NAME  := redaction

.PHONY: all setup install-dev model test test-unit test-integration test-acc \
        test-load lint typecheck dev docker-build docker-run compose-up \
        compose-down deploy-aks deploy-helm clean help

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────

setup: install-dev model
	@echo "✅  Setup complete. Run 'make dev' to start."

install-dev:
	$(PIP) install -r requirements-dev.txt

model:
	@echo "Downloading spaCy model (en_core_web_lg)..."
	$(PYTHON) -m spacy download en_core_web_lg
	@echo "✅  spaCy model downloaded."

# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	pytest tests/unit/ -v --tb=short \
		--cov=src --cov-report=term-missing --cov-report=html:htmlcov \
		-x --timeout=60

test-integration:
	@echo "Running integration tests..."
	pytest tests/integration/ -v --tb=short --timeout=120

test-acc:
	@echo "Running accuracy tests..."
	pytest tests/unit/test_accuracy.py -v --tb=short -s

test-load:
	@echo "Running load test (server must be running at localhost:8000)..."
	locust -f tests/load/locustfile.py \
		--host=http://localhost:8000 \
		--headless -u 100 -r 10 --run-time 60s \
		--csv=results/load_test

test-load-aks:
	@echo "Running load test against AKS..."
	locust -f tests/load/locustfile.py \
		--host=http://$(AKS_EXTERNAL_IP) \
		--headless -u 500 -r 50 --run-time 300s \
		--csv=results/aks_load_test

test-all: test test-acc
	@echo "✅  All tests passed."

# ─────────────────────────────────────────────────────────────────────────────
# Code quality
# ─────────────────────────────────────────────────────────────────────────────

lint:
	ruff check src/ tests/

typecheck:
	mypy src/ --ignore-missing-imports

format:
	ruff format src/ tests/

# ─────────────────────────────────────────────────────────────────────────────
# Local development
# ─────────────────────────────────────────────────────────────────────────────

dev:
	REDACT_ENVIRONMENT=local \
	REDACT_LOG_JSON=false \
	REDACT_LOG_LEVEL=DEBUG \
	REDACT_PIPELINE_WORKERS=4 \
	uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000

demo:
	@echo "Running quick demo..."
	$(PYTHON) scripts/demo.py

# ─────────────────────────────────────────────────────────────────────────────
# Docker
# ─────────────────────────────────────────────────────────────────────────────

docker-build:
	docker build \
		-f deploy/docker/Dockerfile \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-t $(IMAGE_NAME):latest \
		.
	@echo "✅  Built $(IMAGE_NAME):$(IMAGE_TAG)"

docker-run:
	docker run --rm -p 8000:8000 \
		-e REDACT_ENVIRONMENT=local \
		-e REDACT_LOG_JSON=false \
		$(IMAGE_NAME):$(IMAGE_TAG)

compose-up:
	docker compose -f deploy/docker/docker-compose.yml up -d
	@echo "✅  Stack started:"
	@echo "    API:        http://localhost:8000/docs"
	@echo "    Prometheus: http://localhost:9090"
	@echo "    Grafana:    http://localhost:3000 (admin/admin)"

compose-down:
	docker compose -f deploy/docker/docker-compose.yml down

compose-logs:
	docker compose -f deploy/docker/docker-compose.yml logs -f redaction

# ─────────────────────────────────────────────────────────────────────────────
# AKS deployment
# ─────────────────────────────────────────────────────────────────────────────

acr-push: docker-build
	az acr login --name $(ACR_NAME)
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(ACR_NAME).azurecr.io/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(ACR_NAME).azurecr.io/$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "✅  Pushed to ACR"

deploy-aks: acr-push
	kubectl apply -f deploy/k8s/
	kubectl rollout status deployment/pii-redaction -n $(NAMESPACE) --timeout=5m
	@echo "✅  Deployed to AKS"

deploy-helm: acr-push
	helm upgrade --install $(HELM_NAME) ./deploy/helm \
		--namespace $(NAMESPACE) --create-namespace \
		--set image.repository=$(ACR_NAME).azurecr.io/$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG) \
		--wait --timeout 10m
	@echo "✅  Deployed via Helm"

rollback-aks:
	kubectl rollout undo deployment/pii-redaction -n $(NAMESPACE)

aks-status:
	@kubectl get pods -n $(NAMESPACE)
	@kubectl get hpa -n $(NAMESPACE)
	@kubectl get svc -n $(NAMESPACE)

# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf htmlcov/ .coverage results/

results-dir:
	mkdir -p results/

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
