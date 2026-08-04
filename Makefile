.PHONY: test lint typecheck build demo

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/ruff check src tests

typecheck:
	.venv/bin/mypy src

build:
	.venv/bin/python -m build

demo:
	.venv/bin/python examples/scan_demo.py
