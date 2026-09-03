"""Conformance suite (PLAN.md T5): the real python-matter-server client (and, where it hides a
wire detail we care about, a raw websocket) driven against a live server at `MATTER_SERVER_URL`
(default `ws://127.0.0.1:5580/ws`). Run the identical suite against `matter-server --backend mock`
and against `matterjs-server` itself — the latter is the spec (PLAN.md §0.4).

Non-live tests never commission a real device. Live tests (`-m live`) need `LAMP_CODE` and a
lamp in commissioning mode.
"""

from __future__ import annotations

import asyncio
import contextlib
import json

import pytest
from matter_server.client.client import MatterClient
from matter_server.common.models import EventType

from conftest import RawConnection, close_client, make_client, server_url

# A known-good Thread Operational Dataset hex string, lifted verbatim from matterjs-server's own
# test fixtures (packages/ws-controller/test/WebSocketCredentialsApiTest.ts:16). TLV-decodes to
# NetworkName "OpenThread" (type 0x03) and ExtendedPanId 1122334455667788 (type 0x02).
THREAD_DATASET_HEX = (
    "00010f02081122334455667788030a4f70656e5468726561640410"
    "000102030405060708090a0b0c0d0e0f0e080000000000010000"
)
THREAD_NETWORK_NAME = "OpenThread"
THREAD_EXT_PAN_ID = "1122334455667788"


async def wait_for_event(
    client: MatterClient,
    event_type: EventType,
    *,
    node_id: int | None = None,
    attr_path_filter: str | None = None,
    predicate=None,
    timeout: float = 5.0,
):
    """Wait for one event of `event_type` (optionally node/attribute-path filtered).

    Returns `(event_type, data)`. Uses the client's own `subscribe_events` filtering
    mechanism, same as any real subscriber (e.g. Home Assistant) would.
    """
    queue: asyncio.Queue = asyncio.Queue()

    def _on_event(evt: EventType, data: object) -> None:
        if predicate is None or predicate(data):
            queue.put_nowait((evt, data))

    unsubscribe = client.subscribe_events(
        _on_event, event_filter=event_type, node_filter=node_id, attr_path_filter=attr_path_filter
    )
    try:
        return await asyncio.wait_for(queue.get(), timeout=timeout)
    finally:
        unsubscribe()


# ============================================================================
# 1. Raw: on-connect server_info push
# ============================================================================


class TestServerInfoRaw:
    async def test_first_frame_is_bare_server_info(self, raw_connection: RawConnection) -> None:
        info = await raw_connection.recv_json()

        # Bare object: not wrapped in message_id/result or event/data (WIRE_PROTOCOL.md §1/§8).
        assert "message_id" not in info
        assert "event" not in info

        assert info["schema_version"] == 13
        assert info["min_supported_schema_version"] == 11
        assert isinstance(info["fabric_id"], int)
        assert isinstance(info["compressed_fabric_id"], int)
        assert isinstance(info["sdk_version"], str) and info["sdk_version"]
        assert isinstance(info["wifi_credentials_set"], bool)
        assert isinstance(info["thread_credentials_set"], bool)
        assert isinstance(info["bluetooth_enabled"], bool)


# ============================================================================
# 2. Client: connect / start_listening / get_nodes
# ============================================================================


class TestClientConnect:
    async def test_connect_start_listening_get_nodes(self, http_session) -> None:
        c = MatterClient(server_url(), http_session)
        # connect() raises ServerVersionTooOld/TooNew if the client's own schema-version
        # check fails (connection.py) — succeeding here proves schema compatibility.
        await c.connect()
        try:
            assert c.server_info is not None
            assert c.server_info.schema_version == 13
            assert c.server_info.min_supported_schema_version == 11

            ready = asyncio.Event()
            listen_task = asyncio.ensure_future(c.start_listening(ready))
            try:
                await asyncio.wait_for(ready.wait(), timeout=10.0)
                nodes = c.get_nodes()
                assert isinstance(nodes, list)
            finally:
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await listen_task
        finally:
            await c.disconnect()


# ============================================================================
# 3. Raw: error shapes
# ============================================================================


class TestErrorShapes:
    async def test_unknown_command_is_9(self, raw_ready: RawConnection) -> None:
        resp = await raw_ready.call("totally_bogus_command")
        assert resp["error_code"] == 9
        assert isinstance(resp["details"], str) and resp["details"]

    async def test_get_node_unknown_is_5(self, raw_ready: RawConnection) -> None:
        resp = await raw_ready.call("get_node", node_id=424242)
        assert resp["error_code"] == 5

    async def test_subscribe_attribute_is_9(self, raw_ready: RawConnection) -> None:
        # Declared as a wire type only; never reachable in the real dispatch switch
        # (WIRE_PROTOCOL.md §1).
        resp = await raw_ready.call(
            "subscribe_attribute", node_id=424242, attribute_path="1/6/0"
        )
        assert resp["error_code"] == 9

    async def test_write_attribute_wildcard_is_8(self, raw_ready: RawConnection) -> None:
        # matterjs-server rejects wildcard write paths before even looking the node up
        # (WebSocketControllerHandler.ts:1164-1171) — a bogus node id is enough to prove
        # the wildcard check fires and to sidestep needing a real commissioned device.
        resp = await raw_ready.call(
            "write_attribute", node_id=424242, attribute_path="1/6/*", value=True
        )
        assert resp["error_code"] == 8


# ============================================================================
# 4. Credentials
# ============================================================================


class TestCredentials:
    async def test_wifi_credentials_set_and_removed(self, raw_ready: RawConnection) -> None:
        set_resp = await raw_ready.call(
            "set_wifi_credentials", ssid="ssid", credentials="pw"
        )
        assert "error_code" not in set_resp

        info_event = await raw_ready.recv_event("server_info_updated")
        assert info_event["data"]["wifi_credentials_set"] is True

        creds_resp = await raw_ready.call("get_all_credentials")
        creds_text = json.dumps(creds_resp)
        assert "pw" not in creds_text  # secret never leaves the server
        wifi = creds_resp["result"]["wifi"]
        default_entry = next(e for e in wifi if e["id"] == "default")
        assert default_entry == {"id": "default", "ssid": "ssid"}

        remove_resp = await raw_ready.call("remove_wifi_credentials")
        assert remove_resp["result"] == {}
        info_event = await raw_ready.recv_event("server_info_updated")
        assert info_event["data"]["wifi_credentials_set"] is False

        info_resp = await raw_ready.call("server_info")
        assert info_resp["result"]["wifi_credentials_set"] is False

    async def test_thread_dataset_set_and_removed(self, raw_ready: RawConnection) -> None:
        set_resp = await raw_ready.call("set_thread_dataset", dataset=THREAD_DATASET_HEX)
        assert "error_code" not in set_resp

        info_event = await raw_ready.recv_event("server_info_updated")
        assert info_event["data"]["thread_credentials_set"] is True

        creds_resp = await raw_ready.call("get_all_credentials")
        creds_text = json.dumps(creds_resp)
        assert THREAD_DATASET_HEX not in creds_text  # secret dataset never leaves the server
        thread = creds_resp["result"]["thread"]
        default_entry = next(e for e in thread if e["id"] == "default")
        assert default_entry.get("networkName") == THREAD_NETWORK_NAME
        assert default_entry.get("extPanId") == THREAD_EXT_PAN_ID

        remove_resp = await raw_ready.call("remove_thread_dataset")
        assert remove_resp["result"] == {}
        info_event = await raw_ready.recv_event("server_info_updated")
        assert info_event["data"]["thread_credentials_set"] is False


# ============================================================================
# 5. Fabric label ownership
# ============================================================================


class TestFabricLabel:
    async def test_default_fabric_label_and_ownership(self, http_session) -> None:
        conn_a = await make_client(http_session)
        conn_b = await make_client(http_session)
        try:
            result = await conn_a.set_default_fabric_label("Home")
            assert result is None
            assert await conn_a.get_fabric_label() == "Home"

            # A second, still-open connection cannot steal ownership of the label
            # (WIRE_PROTOCOL.md §11): silent no-op, `null` result, label unchanged.
            result = await conn_b.set_default_fabric_label("Other")
            assert result is None
            assert await conn_b.get_fabric_label() == "Home"
            assert await conn_a.get_fabric_label() == "Home"
        finally:
            await close_client(conn_a)
            await close_client(conn_b)


# ============================================================================
# 6. Diagnostics / vendor names / discover
# ============================================================================


class TestDiagnosticsAndDiscovery:
    async def test_diagnostics_shape(self, client: MatterClient) -> None:
        diag = await client.get_diagnostics()
        assert diag.info is not None
        assert isinstance(diag.nodes, list)
        assert isinstance(diag.events, list)

    async def test_get_vendor_names_is_object(self, raw_ready: RawConnection) -> None:
        resp = await raw_ready.call("get_vendor_names")
        assert isinstance(resp["result"], dict)

    async def test_discover_is_list(self, client: MatterClient) -> None:
        result = await client.discover_commissionable_nodes()
        assert isinstance(result, list)


# ============================================================================
# 7. Live tests: need a real lamp in commissioning mode (LAMP_CODE)
# ============================================================================


@pytest.mark.live
class TestLiveLamp:
    async def test_commission_read_toggle_remove(self, client: MatterClient, lamp_code: str) -> None:
        from chip.clusters import Objects as Clusters

        node_added = wait_for_event(client, EventType.NODE_ADDED, timeout=60.0)
        node_data = await client.commission_with_code(lamp_code, network_only=True)
        node_id = node_data.node_id

        _, added_node = await node_added
        assert added_node.node_id == node_id

        assert "0/40/1" in node_data.attributes  # Basic Information VendorName
        assert "1/6/0" in node_data.attributes  # OnOff

        attrs = await client.read_attribute(node_id, "1/6/0")
        assert isinstance(attrs, dict)
        assert "1/6/0" in attrs
        assert isinstance(attrs["1/6/0"], bool)

        for _ in range(2):
            update = wait_for_event(
                client,
                EventType.ATTRIBUTE_UPDATED,
                node_id=node_id,
                attr_path_filter="1/6/0",
                timeout=5.0,
            )
            await client.send_device_command(
                node_id=node_id, endpoint_id=1, command=Clusters.OnOff.Commands.Toggle()
            )
            _, new_value = await update
            assert isinstance(new_value, bool)

        fabrics = await client.get_matter_fabrics(node_id)
        assert any(f.fabric_id == client.server_info.fabric_id for f in fabrics)

        node_removed = wait_for_event(client, EventType.NODE_REMOVED, timeout=30.0)
        await client.remove_node(node_id)
        _, removed_id = await node_removed
        assert removed_id == node_id  # bare node id, not wrapped (WIRE_PROTOCOL.md §3)
