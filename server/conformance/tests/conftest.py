"""Shared fixtures for the conformance suite (PLAN.md T5).

Everything here is parametrised by `MATTER_SERVER_URL` (default
`ws://127.0.0.1:5580/ws`) so the exact same suite runs against `matter-server
--backend mock` and against a real `matterjs-server`.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator

import aiohttp
import pytest
import pytest_asyncio
from matter_server.client.client import MatterClient

DEFAULT_URL = "ws://127.0.0.1:5580/ws"


def server_url() -> str:
    return os.environ.get("MATTER_SERVER_URL", DEFAULT_URL)


@pytest_asyncio.fixture
async def http_session() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


class RawConnection:
    """Thin raw-websocket helper for wire details the high-level client hides or
    post-processes (exact error frames, the on-connect push, raw event arrays).
    """

    def __init__(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        self.ws = ws
        self._next_id = 1
        # Frames read by recv_response/recv_event that didn't match what they were looking
        # for are kept here (order preserved) so a later, differently-targeted read can still
        # find them — a response and an event it triggers can arrive in either order.
        self._buffer: list[dict] = []

    async def recv_json(self, timeout: float = 5.0) -> dict:
        msg = await asyncio.wait_for(self.ws.receive(), timeout=timeout)
        assert msg.type == aiohttp.WSMsgType.TEXT, f"unexpected frame type: {msg.type!r} {msg.data!r}"
        return msg.json()

    async def send(self, command: str, **args: object) -> str:
        message_id = str(self._next_id)
        self._next_id += 1
        await self.ws.send_json({"message_id": message_id, "command": command, "args": args})
        return message_id

    async def call(self, command: str, timeout: float = 5.0, **args: object) -> dict:
        """Send a command and return its response frame (result or error), skipping
        any events that arrive interleaved with it.
        """
        message_id = await self.send(command, **args)
        return await self.recv_response(message_id, timeout=timeout)

    async def _recv_matching(self, matches, timeout: float, what: str) -> dict:
        for i, frame in enumerate(self._buffer):
            if matches(frame):
                return self._buffer.pop(i)
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            assert remaining > 0, f"never got {what}"
            frame = await self.recv_json(timeout=remaining)
            if matches(frame):
                return frame
            self._buffer.append(frame)

    async def recv_response(self, message_id: str, timeout: float = 5.0) -> dict:
        return await self._recv_matching(
            lambda f: f.get("message_id") == message_id, timeout, f"a response for message_id={message_id}"
        )

    async def recv_event(self, event: str, timeout: float = 5.0) -> dict:
        """Read frames until one matching `event` arrives (skipping command responses
        and other events interleaved with it).
        """
        return await self._recv_matching(lambda f: f.get("event") == event, timeout, f"event {event!r}")


@pytest_asyncio.fixture
async def raw_connection(http_session: aiohttp.ClientSession) -> AsyncIterator[RawConnection]:
    """A bare websocket connection with the initial `server_info` push still unread,
    for tests that need to inspect it directly.
    """
    async with http_session.ws_connect(server_url()) as ws:
        yield RawConnection(ws)


@pytest_asyncio.fixture
async def raw_ready(raw_connection: RawConnection) -> AsyncIterator[RawConnection]:
    """A raw connection with the initial `server_info` push already drained."""
    await raw_connection.recv_json()
    yield raw_connection


async def make_client(http_session: aiohttp.ClientSession) -> MatterClient:
    """Connect + start_listening a `MatterClient`, exactly like Home Assistant does.

    The background `start_listening` loop is stashed on the instance (`_listen_task`)
    so `close_client` can cancel it; use this (instead of a fixture) whenever a test
    needs more than one independently lifecycled connection.
    """
    c = MatterClient(server_url(), http_session)
    await c.connect()
    ready = asyncio.Event()
    listen_task = asyncio.ensure_future(c.start_listening(ready))
    await asyncio.wait_for(ready.wait(), timeout=10.0)
    c._listen_task = listen_task  # type: ignore[attr-defined]
    return c


async def close_client(c: MatterClient) -> None:
    await c.disconnect()
    task = getattr(c, "_listen_task", None)
    if task is not None:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest_asyncio.fixture
async def client(http_session: aiohttp.ClientSession) -> AsyncIterator[MatterClient]:
    """A connected, listening `MatterClient` — exactly what Home Assistant drives."""
    c = await make_client(http_session)
    try:
        yield c
    finally:
        await close_client(c)


@pytest.fixture
def lamp_code() -> str:
    code = os.environ.get("LAMP_CODE")
    if not code:
        pytest.skip("LAMP_CODE not set; skipping live test")
    return code
