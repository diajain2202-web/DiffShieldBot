.PHONY: test demo scene tunnel run lint

PYTHON ?= python

test:
	$(PYTHON) -m pytest tests -q

demo:
	$(PYTHON) -m engine.cli demo

scene:
	$(PYTHON) scripts/demo_local.py

run:
	$(PYTHON) run.py

tunnel:
	@echo "Starting local webhook tunnel..."
	@echo "Install smee-client (npm install -g smee-client) or cloudflared"
	@echo "Example: smee --url https://smee.io/YOUR_CHANNEL --target http://localhost:8000/webhook"
	smee --target http://localhost:8000/webhook

lint:
	$(PYTHON) -m pytest tests --collect-only

