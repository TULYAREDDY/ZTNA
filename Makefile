.PHONY: help install backend proxy frontend train demo clean ensure-model

PYTHON ?= python3
MODEL := backend/app/ml/artifacts/model.joblib

help:
	@echo "Sentinel ZTNA — common targets"
	@echo "  make install     install backend, proxy, and frontend deps"
	@echo "  make train       generate dataset + train ML model"
	@echo "  make backend     run the FastAPI Policy Decision Point on :8000"
	@echo "  make proxy       run the Policy Enforcement Point on :9090"
	@echo "  make frontend    run the React dashboard on :5173"
	@echo "  make demo        backend + frontend in parallel (recommended)"
	@echo "  make clean       wipe Python caches & ML artifacts"

install:
	cd backend  && $(PYTHON) -m venv .venv && .venv/bin/pip install -r requirements.txt
	cd proxy    && $(PYTHON) -m venv .venv && .venv/bin/pip install -r requirements.txt
	cd frontend && npm install

ensure-model:
	@test -f $(MODEL) || $(MAKE) train

train:
	cd backend && .venv/bin/python -m app.ml.train

backend: ensure-model
	cd backend && .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

proxy:
	cd proxy && .venv/bin/python ztna_proxy.py

frontend:
	cd frontend && npm run dev

demo: ensure-model
	@echo "▶ starting backend + frontend… (Ctrl+C to stop both)"
	@(cd backend && .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &) ; \
	 (cd frontend && npm run dev)

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf backend/app/ml/artifacts/*.png backend/app/ml/artifacts/model.joblib backend/app/ml/artifacts/metrics.json
