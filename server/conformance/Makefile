# Conformance harness (PLAN.md T5). Runs the real python-matter-server client against a live
# server. See README.md for details and manual invocations.

.PHONY: sync test-mock test-mc test-matterjs test-live clean

sync:
	uv sync

# Boots `matter-server --backend mock` from ../target/debug on a random free port, runs the
# non-live suite against it, then kills it.
test-mock: sync
	@bash run-mock.sh

# Boots `matter-server --backend mc` from ../target/debug on a random free port, runs the
# non-live suite against it, then kills it.
test-mc: sync
	@bash run-mc.sh

# Expects a running matterjs-server (or matter-server) at MATTER_SERVER_URL
# (default ws://127.0.0.1:5580/ws). Start one first — see README.md.
test-matterjs: sync
	uv run pytest -v -m "not live" tests/

# Live tests need LAMP_CODE set and a lamp in commissioning mode, against whatever
# MATTER_SERVER_URL already has running.
test-live: sync
	uv run pytest -v -m live tests/

clean:
	rm -rf .venv
