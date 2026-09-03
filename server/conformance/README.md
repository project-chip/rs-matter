# Conformance harness (PLAN.md T5)

A `uv` project that drives the real `python-matter-server` client
(`matterjs-server/python_client`, package name `matter-python-client`) — the
same library Home Assistant's Matter integration uses — against a live
server over the WS wire protocol. The suite is parametrised by
`MATTER_SERVER_URL` (default `ws://127.0.0.1:5580/ws`), so the exact same
tests run against `matter-server --backend mock` and against `matterjs-server`
itself (the conformance oracle — PLAN.md §0.4).

Where the high-level client hides or post-processes a wire detail we care
about (the exact error frame, the on-connect `server_info` push, the raw
`attribute_updated` array), `tests/conftest.py`'s `RawConnection` talks
`aiohttp` websockets directly and asserts on the JSON.

## Setup

```sh
uv sync
```

This resolves `matter-python-client` as a path dependency on
`../../matterjs-server/python_client` (see `pyproject.toml`'s
`[tool.uv.sources]`) — no separate install step needed.

## Running

```sh
make test-mock        # boots matter-server --backend mock itself, runs, tears down
make test-matterjs     # needs a server already running at MATTER_SERVER_URL
make test-live         # live tests only; needs LAMP_CODE + a lamp in commissioning mode
```

Or invoke pytest directly once a server is up:

```sh
MATTER_SERVER_URL=ws://127.0.0.1:5580/ws uv run pytest -v -m "not live" tests/
```

### Starting matterjs-server as the oracle

Node.js >= 22.13 is required.

```sh
cd ../../matterjs-server
npm i          # runs the full build (tsc + esbuild + dashboard bundle) via `prepare`
npm run server -- --storage-path /tmp/mjs --port 5580
```

Then, in another shell:

```sh
cd ../server/conformance
MATTER_SERVER_URL=ws://127.0.0.1:5580/ws uv run pytest -v -m "not live" tests/
```

Note: on a very first cold start, matterjs-server can occasionally miss its
first WebSocket connection while its `ws` upgrade handler finishes wiring up
(observed once during development; a fresh connection after a moment succeeds
and every connection after that behaves normally). If the very first test
after starting the server times out waiting on the `server_info` push, retry
once.

### Live tests

Live tests (`@pytest.mark.live`, `TestLiveLamp`) commission a real lamp,
toggle it, and remove it again. They need:

- `LAMP_CODE` set to a QR or manual pairing code for a lamp currently in
  commissioning mode.
- A server (mock or matterjs-server) already running at `MATTER_SERVER_URL`.

```sh
LAMP_CODE="34970112332" MATTER_SERVER_URL=ws://127.0.0.1:5580/ws uv run pytest -v -m live tests/
```

They are skipped automatically (not failed) when `LAMP_CODE` is unset.

## What's verified where

See PLAN.md T5 for the full list. In short: on-connect `server_info` shape
and types; `connect()`/`start_listening()`/`get_nodes()`; error codes for an
unknown command, an unknown node, `subscribe_attribute`, and a wildcard
`write_attribute` path; Wi-Fi/Thread credential set/get/remove (secrets never
leave the server) plus the `server_info_updated` broadcast; fabric label
ownership across two live connections; `diagnostics`/`get_vendor_names`/
`discover` shapes; and, gated behind `LAMP_CODE`, a full commission → read →
toggle → fabrics → remove cycle against a real device.
