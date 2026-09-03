# WebSocket wire protocol — exact spec extracted from the matterjs-server TypeScript

Source of truth: `matterjs-server` v1.4.1-alpha.2 (commit 1e489f4). Read from:

- `packages/ws-controller/src/server/WebSocketControllerHandler.ts` (WSH)
- `packages/ws-controller/src/controller/ControllerCommandHandler.ts` (CCH)
- `packages/ws-controller/src/types/WebSocketMessageTypes.ts` (WMT)
- `packages/ws-client/src/models/model.ts` (M), `packages/ws-client/src/models/node.ts` (N)
- `packages/ws-controller/src/server/Converters.ts` (CONV) — value/path conversion, bigint JSON
- `packages/ws-controller/src/server/WebSocketConnection.ts`, `serializeBatch.ts`,
  `controller/Nodes.ts`, `controller/AttributeDataCache.ts`, `server/ConfigStorage.ts`

Line numbers are for that commit. When in doubt, open the file.

## 0. Numbers

All outgoing frames go through `toBigIntAwareJson` (CONV:470-497): bigints are
emitted as **bare unquoted decimal integers**, even above 2^53. Incoming frames
use `parseBigIntAwareJson` (CONV:508-610). Node ids, fabric ids, event numbers
and timestamps are therefore plain JSON numbers, never strings. A Rust server
must emit `u64` directly and parse integer literals without going through f64.

## 1. Frames

Request: `{"message_id": string, "command": string, "args": {...}}`.

Success (M:832-834): `{"message_id": string, "result": <any>}`.

Error (WSH:845-858, M:827-830):
```json
{"message_id": "42", "error_code": 5, "details": "Node 1234 does not exist"}
```
`error_code` = `err.code` if the throw was a `ServerError`, else `0`. `details`
is `err.message` (typed optional, always present in practice).

`ServerErrorCode` (WMT:57-86):

| code | name |
|---|---|
| 0 | UnknownError |
| 1 | NodeCommissionFailed |
| 2 | NodeInterviewFailed |
| 3 | NodeNotReady |
| 4 | NodeNotResolving |
| 5 | NodeNotExists |
| 6 | VersionMismatch |
| 7 | SDKStackError |
| 8 | InvalidArguments |
| 9 | InvalidCommand |
| 10 | UpdateCheckError |
| 11 | UpdateError |
| 100 | IcdMultiAdmin (OHF ext.) — `details` is a JSON **string**: `{"message": string, "admin_vendor_ids": number[]}` (WMT:154-162) |
| 101 | OtaUploadError (OHF ext.) |

Unknown command → `InvalidCommand` (9) (WSH:824-825). This includes
`subscribe_attribute`: it exists only as a type in M:536-539 and is **not**
in the dispatch switch, so today it errors with 9.

Event: always `{"event": "<name>", "data": <payload>}` (WSH:296, 356, 383,
441, 636, 887-905). Delivery modes (`WebSocketConnection.ts`): command
responses / `server_info` / `server_shutdown` are `sendReliable`; structural
events (`node_added`, `node_removed`, `endpoint_*`, `node_event`) are
`sendOrdered` (FIFO, oldest dropped under backpressure; `node_added` is never
dropped); `node_updated` is coalesced per node (`node:<id>`), `attribute_updated`
per path (`attr:<node>/<path>`), latest wins. Shapes are unaffected.

On connect the server pushes a `server_info` **message** (not an event — a bare
`ServerInfoMessage` object, §8) before any request.

## 2. Node object (`MatterNodeData`, N:8-25; built in CCH:870-881)

```json
{
  "node_id": 1234,
  "date_commissioned": "2026-09-03T10:15:30.123000",
  "last_interview": "2026-09-03T10:15:30.123000",
  "interview_version": 6,
  "available": true,
  "is_bridge": false,
  "attributes": {"0/29/0": [...], "1/6/0": true, "1/8/0": 254},
  "attribute_subscriptions": [],
  "matter_version": "1.3.0"
}
```
- Dates: `getDateAsString` (CONV:728-739) → `YYYY-MM-DDTHH:mm:ss.mmm000`
  (microseconds always `000`).
- `interview_version` is always `6`.
- `is_bridge`: endpoint 1's Descriptor `DeviceTypeList` (`1/29/0`) contains an
  entry whose `"0"` (deviceType tag) equals `14` (Aggregator) (CCH:863-868).
- `matter_version`: from `0/40/21` (`SpecificationVersion`) if present, else
  from `0/40/0` (`DataModelRevision`): `<=16` → `"<1.2.0"`, `17` → `"1.2.0"`,
  else key omitted (CCH:132-154).
- `attributes`: flat object keyed `"endpoint/cluster/attribute"` (decimal).
  Values use **tag-based** conversion (`convertMatterToWebSocketTagBased`,
  CONV:346-463 with `tagBased=true`): struct fields keyed by the **numeric
  TLV context tag as a string** — `{"0": 1, "1": "foo"}`, never field names.
  Lists are JSON arrays. Read CONV:346-463 for enum/bitmap/octet-string/
  nullable encodings before implementing.
- `attribute_subscriptions`: always `[]`.
- Test nodes have `node_id >= 0xFFFF_FFFE_0000_0000` and the same shape.

## 3. Events

### node_added / node_updated
`data` = full node object (§2). WSH:287-304. `node_updated` is coalesced per
node. Emitted by `interview_node`, `register_icd`, `unregister_icd`, structure
changes, availability changes.

### node_removed
`data` = bare node id: `{"event":"node_removed","data":1234}` (WSH:356, 513).

### attribute_updated
`data` = `[node_id, "endpoint/cluster/attribute", value]` (WSH:362-391),
value tag-based as in §2. Source: matter.js's single whole-node subscription
established at `node.connect()`; nothing a client does creates or removes it.

### endpoint_added / endpoint_removed
`data` = `{"node_id": 1234, "endpoint_id": 3}` (WSH:480-501). `endpoint_added`
is deliberately sent **after** the `node_updated` carrying the new endpoint
(Nodes.ts:27-31) — HA resolves `node.endpoints[endpoint_id]` on receipt.

### node_event
`data` (`MatterNodeEvent`, WMT:676-686; built WSH:393-448):
```json
{"node_id": 1234, "endpoint_id": 1, "cluster_id": 59, "event_id": 1,
 "event_number": 12345, "priority": 1, "timestamp": 1704067200000,
 "timestamp_type": 1, "data": {"newPosition": 1}}
```
`timestamp_type`: 1 = epoch timestamp present, 0 = system timestamp, 2 =
neither (server used `Date.now()`). `data` uses **name-based** conversion
(`convertMatterToWebSocketNameBased`) — camelCase wire field names — or `null`.

### server_info_updated
`data` = `ServerInfoMessage` (§8). Broadcast after any credential change.

### server_shutdown
`data` = `{}` (WSH:636).

### thread_diagnostics_updated / network_topology_updated
See §21. Delivered only to connections that issued the matching command.

## 4. get_nodes / get_node / start_listening

- `get_nodes` args `{only_available?: bool}` → **array** of node objects
  (real + test nodes) (WSH:1097-1114).
- `get_node` args `{node_id}` → one node object; unknown → error 5
  (WSH:1116-1131). Awaits population first.
- `start_listening` → same array as `get_nodes`; from then on the connection
  receives events (WSH:916-921).

## 5. read_attribute

Args (M:540-549): `{node_id, attribute_path: string | string[], fabric_filtered?: bool}`
(`fabric_filtered` default false). Paths split by `splitAttributePath`
(CONV:753-780): each component is a decimal integer or a wildcard; **any
non-numeric token** (`*`, empty, missing) and the sentinels `0xFFFF`
(endpoint) / `0xFFFFFFFF` (cluster/attribute) mean wildcard. Reads are batched
9 paths per IM read (CCH:887-936).

Result: **flat object**, `{"1/6/0": true, "1/8/0": 254}`, tag-based values.
Attributes that came back with an error status are logged and omitted. If the
merged object is empty → error 7 `"Failed to read attribute: no values returned"`.

## 6. write_attribute

Args (M:550-560): `{node_id, attribute_path: string, value}`. Wildcards →
error 8. `value` is tag-based (struct keys are numeric-string tags; field names
are tolerated for old clients) and converted with the cluster model
(CCH:1017-1039; unknown cluster/attribute → error 8).

Result — always a one-element array with **PascalCase** keys (the only
PascalCase shape in the API):
```json
[{"Path": {"EndpointId": 1, "ClusterId": 6, "AttributeId": 0}, "Status": 0}]
```
`Status` = 0 on success, else the IM status code.

## 7. device_command

Args read (WSH:1223-1267): `node_id, endpoint_id, cluster_id, command_name,
payload, timed_request_timeout_ms?`. `response_type` and
`interaction_timeout_ms` are declared but **never read**.

- `command_name` is `camelize()`d (`"MoveToLevel"`, `"move_to_level"` →
  `"moveToLevel"`) and looked up **by name** on the cluster's command list
  (CCH:1067-1099). Unknown cluster/command → error 8.
- `payload`: object keyed by **field name** (camelCase); `{}` → no fields;
  converted with `convertCommandDataToMatter`. In-flight identical invokes
  are deduplicated (CCH:1101-1112).
- Result: response fields converted **name-based** (WSH:1618-1641,
  CONV:413-431): keys are the wire field name, and additionally the matter.js
  property name when it differs. Status-only success → `null`. Unknown
  cluster/command model → `{}`. Test nodes → `null`.

## 8. server_info (message on connect, command result, `server_info_updated` data)

WSH:861-882, M:699-715:
```json
{"fabric_id": 1, "compressed_fabric_id": 9876543210, "fabric_index": 1,
 "schema_version": 13, "min_supported_schema_version": 11,
 "sdk_version": "matter-server/1.4.1 (matter.js/0.17.5)",
 "wifi_credentials_set": true, "wifi_ssid": "MyWifi",
 "thread_credentials_set": false, "bluetooth_enabled": false,
 "ble_proxy_enabled": false, "controller_node_id": 112233}
```
`fabric_index`, `ble_proxy_enabled`, `controller_node_id` are OHF-only
extensions (python-matter-server doesn't have them). `wifi_ssid` is omitted
unless both SSID and password are stored.

## 9. commission_with_code / commission_on_network

Both return the full node object of the new node (§2). Node id collision
retried up to 5 times (WSH:975-1000).

`commission_with_code` (WSH:1002-1048): args `{code, network_only?,
wifi_credentials_id?, thread_dataset_id?}`. `code` starting `"MT:"` is a QR
payload, else a manual pairing code. `network_only` disables BLE discovery
and credential push entirely. Credential ids default to `"default"`.

`commission_on_network` (WSH:1050-1095): args `{setup_pin_code, filter_type?,
filter?, ip_addr?}`. Always network-only. `filter_type`: 0 none, 1 short
discriminator, 2 long discriminator, 3 vendor id (product id 0), 4 device type
(**not implemented**, falls back to unfiltered). `filter` is required for
1/2/3 (else error 8). `ip_addr` becomes a known address on port 5540 unless
it starts with `fe80` (link-local is ignored).

## 10. open_commissioning_window

Args `{node_id, timeout?, iteration?, option?, discriminator?}` — only
`node_id` and `timeout` are used; window is always Enhanced (WSH:1505-1516,
CCH:1467-1472). Result (M:871-875):
```json
{"setup_pin_code": 20202021, "setup_manual_code": "34970112332", "setup_qr_code": "MT:Y.K9042C00KA0648G00"}
```

## 11. Credentials and fabric label

Reserved credential ids: `"default"`, `"delete"` (ConfigStorage.ts:26-27).

- `set_wifi_credentials` `{ssid, credentials, id?}`; `set_thread_dataset`
  `{dataset, id?}`. Both broadcast `server_info_updated`.
- `get_all_credentials` → (WSH:1439-1458, M:694-697)
  `{"wifi": [{"id": "default", "ssid": "MyWifi"}], "thread": [{"id": "default", "networkName": "...", "extPanId": "1122334455667788"}]}`
  — a `"default"` entry is always present (synthesised `ssid: ""` /
  `{id}` if unset); `extPanId` uppercase hex; never any secret.
- `remove_wifi_credentials` / `remove_thread_dataset` `{id?}` → `{}`, then
  `server_info_updated` (WSH:1420-1437).
- `get_fabric_label` → `{"fabric_label": string | null}` (WSH:964-966).
- `set_default_fabric_label` `{label}` → `null` always (WSH:923-962).
  `normalizeFabricLabel`: trim; empty → `"HomeAssistant"`; max 32 chars. If
  the label is CLI-pinned, or another live connection already owns it, the
  call is a **silent no-op** (still `null`, no error). First connection to
  succeed owns the label until it disconnects (WSH:572-575).

## 12. get_matter_fabrics / remove_matter_fabric

`get_matter_fabrics` `{node_id}` → live read of the device's
`OperationalCredentials.fabrics` (CCH:1474-1507), mapped (WSH:1565-1582):
```json
[{"fabric_id": 1, "vendor_id": 65521, "fabric_index": 1, "fabric_label": "HomeAssistant", "vendor_name": "Test Vendor"}]
```
`vendor_name` from the static `data/VendorIDs.js` table, omitted if unknown.
`remove_matter_fabric` `{node_id, fabric_index}` → `{}`.

## 13. set_acl_entry / set_node_binding

Args (WMT:648-667):
```json
{"node_id": 1, "entry": [{"privilege": 5, "auth_mode": 2, "subjects": [112233], "targets": null}]}
{"node_id": 1, "endpoint": 1, "bindings": [{"node": 2, "group": null, "endpoint": 1, "cluster": 6}]}
```
Targets: `{cluster, endpoint, device_type}` each nullable. `fabric_index` is
never client-supplied: the server fills every entry with the node's
`OperationalCredentials.currentFabricIndex` (CCH:1584-1651); subjects equal to
the target node's own id are stripped. Result (WMT:670-673, lowercase keys):
```json
[{"path": {"endpoint_id": 0, "cluster_id": 31, "attribute_id": 0}, "status": 0}]
```
(`cluster_id` 30 / given endpoint for bindings.)

## 14. ICD

`IcdStateData` (WMT:912-921):
```json
{"supported": true, "lit_supported": true, "registered": true, "operating_mode": "LIT",
 "awake": false, "available": true, "next_expected_checkin": 1735689600000}
```
No `IcdManagement` cluster on ep0 → `supported:false`, the rest `false`/`null`
(CCH:1554-1582). `operating_mode` from the `OperatingMode` attribute
(`Lit` → `"LIT"`, else `"SIT"`); `registered/awake/available/next_expected_checkin/
lit_supported` from the controller's own ICD client state.

- `get_icd_state` `{node_id}` → IcdStateData.
- `register_icd` `{node_id, allow_multi_admin?, ignored_vendors?}` →
  IcdStateData, plus a `node_updated` broadcast. May raise error 100.
- `unregister_icd` `{node_id, force?}` → IcdStateData, plus `node_updated`.
- `resync_icd` `{node_id}` → `null`.
Test nodes → error 8 for all four.

## 15. diagnostics

`{"info": ServerInfoMessage, "nodes": [node objects], "events": [last 25 MatterNodeEvent]}`
(WSH:748-754, history size 25 at WSH:76).

## 16. ping_node

Args `{node_id, attempts?}` (default 1). Result `{"<ip>": bool, ...}` keyed by
each resolved address (scoped `%iface` kept in the key, stripped for the
actual ping). Always does a fresh address lookup (`prefer_cache=false`); no
addresses → `{}` (CCH:1395-1433).

## 17. get_node_ip_addresses

Args `{node_id, prefer_cache?, scoped?}` → `string[]`. Union, insertion order,
deduped (CCH:1322-1354): cached mDNS peer addresses → (if `!prefer_cache` or
none) live 3 s mDNS SRV query → newest session's peer ip → commissioning-time
addresses. `prefer_cache` defaults to **true** when omitted. `scoped=false`
(default) strips `%iface`.

## 18. discover / discover_commissionable_nodes

`discover` == `discover_commissionable_nodes({})`. 3 s `_matterc._udp` scan;
only the **last** result is returned, as a one-element array (or `[]`)
(CCH:1275-1320). Element (WSH:1518-1563, M:877-894):
```json
{"instance_name": "...", "host_name": "000000000000", "port": 5540,
 "long_discriminator": 3840, "vendor_id": 65521, "product_id": 32768,
 "commissioning_mode": 1, "device_type": 257, "device_name": "...",
 "pairing_instruction": "...", "pairing_hint": 33,
 "mrp_retry_interval_idle": 500, "mrp_retry_interval_active": 300,
 "supports_tcp": false, "addresses": ["192.168.1.5"], "rotating_id": "..."}
```
`host_name` is currently the literal placeholder `"000000000000"`.

## 19. import_test_node

`{dump: string}` → `null`; `node_added` events follow asynchronously
(WSH:1594-1600).

## 20. get_vendor_names

`{filter_vendors?: number[]}` → `{"<vendor id decimal string>": "<name>"}`;
static table merged with DCL (DCL wins); filter drops unknown ids silently
(WSH:1188-1221).

## 21. Thread / topology

- `get_thread_border_routers` → `BorderRouterEntry[]` (`@matter/thread-br-client`):
  `extAddressHex, extendedPanIdHex?, networkName?, vendorName?, modelName?,
  hostname?, addresses: string[], meshcopPort?, trelPort?, threadVersion?,
  swVersion?, recordVersion?, borderAgentIdHex?, stateBitmapHex?,
  activeTimestampHex?, partitionIdHex?, domainName?, sources: ("meshcop"|"trel")[],
  lastSeen: number`.
- `get_thread_diagnostics` `{ext_pan_id?, force?}` (WSH:1392-1408): without
  `ext_pan_id` → array of all cached batches and a background refresh; with a
  16-hex-char `ext_pan_id` → one batch or `null`. Batch
  (`ThreadDiagnosticsBatch`, N:197-212): `{extPanIdHex, networkName,
  collectedAt, source: "meshcop"|"otbr-rest"|"none", nodes: ThreadDiagnosticsNode[],
  partialReason?}`. Node fields all optional (N:135-173): `extMacAddress,
  rloc16, mode{rxOnWhenIdle,ftd,fullNetworkData}, timeout, connectivity,
  route64{idSequence,entries[{routerId,linkQualityIn,linkQualityOut,routeCost}]},
  leaderData{partitionId,weighting,dataVersion,stableDataVersion,leaderRouterId},
  networkData, ipv6Addresses[], macCounters, childTable[{timeoutExponent,
  timeoutSeconds,incomingLinkQuality,childId,mode}], channelPages[],
  maxChildTimeout, eui64, version, vendorName, vendorModel, vendorSwVersion,
  threadStackVersion, vendorAppUrl, mleCounters, batteryLevel, supplyVoltage,
  unknown[{type,value}]`. Same shape as `thread_diagnostics_updated` data.
- `get_network_topology` `{refresh?}` → `NetworkTopology` (N:329-334)
  `{collected_at, nodes: NetworkTopologyNode[], connections: NetworkTopologyConnection[]}`.
  Node (N:259-301): `id` (decimal node id, or `br_<XA>`, `unknown_<EXT>`,
  `ap_<BSSID>`), `kind: "matter"|"border_router"|"thread_unknown"|"wifi_ap"`,
  `network_type: "thread"|"wifi"|"ethernet"|"unknown"`, optional `node_id,
  role, available, is_bridge, ext_address, rloc16, ext_pan_id, network_name,
  ssid, bssid, host_name, vendor_name, model_name, last_seen`.
  Connection (N:309-323): `{source, target, network: "thread"|"wifi",
  strength: "strong"|"medium"|"weak"|"none"|"unknown", source_to_target?
  {strength, lqi?, rssi?}, target_to_source?, via_route_table?, path_cost?}`.
  Same shape as `network_topology_updated` data.

## 22. OTA

- `initiate_ota_upload` (no args) → `{"upload_id": string, "expires_in": secs, "max_size": bytes}`
  (M:865-869); upload is `POST /ota-upload/<upload_id>` raw bytes.
- `check_node_update` `{node_id}` → `MatterSoftwareVersion | null` (M:849-859):
  `{vid, pid, software_version, software_version_string, firmware_information?,
  min_applicable_software_version, max_applicable_software_version,
  release_notes_url?, update_source: "main-net-dcl"|"test-net-dcl"|"local"}`.
  Server synthesises `min_applicable_software_version = 0` and
  `max_applicable_software_version = software_version - 1` (CCH:1808-1825).
  OTA disabled → error 10.
- `update_node` `{node_id, software_version: number|string}` → same shape or
  `null`; refuses if the node's `0/42/2` UpdateState is not Idle (error 11).

## 23. Subscriptions

One whole-node attribute+event subscription per node, established by
matter.js at `node.connect()` (CCH:567-649, 770). Every report updates the
attribute cache (AttributeDataCache.ts:74-102) and emits `attribute_updated`.
Clients cannot add or remove subscriptions.

## 24. Tag-based value encoding (task T2 follow-up)

Read from `packages/ws-controller/src/server/Converters.ts` (commit 1e489f4), specifically
`convertMatterToWebSocketTagBased`/`convertMatterToWebSocket` (CONV:345-463, `tagBased=true`
branch) for the outgoing direction and `convertWebSocketTagBasedToMatter` +
`convertWebSocketGenericToMatter` (CONV:196-198, 260-300, 405-461) for the incoming direction.
This is the **schema-less** shape this crate implements (`ws-protocol::value::MValue`); the
schema-driven parts (bitmap/epoch conversion, wire-field-name struct fallback) need a
`ClusterModel` and belong to `matter-names` (T3), not this crate — see the per-item notes below.

- **Octet strings are bare base64, not `{"$bytes": hex}`.** `ConvKind.Bytes` (CONV:397-398):
  `value instanceof Uint8Array ? Bytes.toBase64(value) : value`. Incoming:
  `convertWebSocketGenericToMatter` (CONV:196-198): `typeof value === "string" &&
  model.metabase?.metatype === "bytes"` -> `Bytes.fromBase64(value)`. There is no wrapper object
  at any point — the distinction between "this string is text" and "this string is bytes" is
  carried entirely by the `ValueModel`, never by the JSON shape. `ws-protocol::MValue::Bytes`
  therefore encodes to a bare base64 `Json::String` (`value.rs`, `Engine::encode`), and decoding a
  JSON string always yields `MValue::Str` — a schema-aware caller (`matter-names`, once it exists)
  re-wraps it as `Bytes` when it knows the attribute/field is octet-string typed. This crate has no
  `ClusterModel`, so it cannot make that call itself; this is documented as an explicit scope
  boundary in `value.rs`, not a gap.
- **`null` passes through unconditionally.** `convertMatterToWebSocket` returns `null` for a
  `null` input before even looking at the model (CONV:369-371); the reverse
  (`convertWebSocketTagBasedToMatter`, CONV:369-372 in the earlier block / the `model === undefined
  || value === null` guard) does the same. No `Some`/`None` distinction, no "was this field
  omitted" tracking — `MValue::Null <-> Json::Null`, always.
- **Floats and enums/bitmaps-as-numbers fall through as bare JSON numbers.** `classifyModel`
  (CONV:571-587) only special-cases `list`, `struct`, `bitmap`, `bytes`, and `epoch-s`/`epoch-us`
  integers; every other metatype — including `float`/`double` and plain `enum`/`integer` — resolves
  to `ConvKind.Passthrough`, which returns the JS value unchanged (a `number`). So `MValue::F32`/
  `F64` encode as ordinary `Json::Number` values (`Number::from_f64`), never a wrapped or
  string-tagged float.
- **`bigint` (u64/i64 wire fields) is a bare, unquoted, full-precision decimal integer**, via
  `toBigIntAwareJson` (CONV:481-497 in the file map cited in §0): values above
  `Number.MAX_SAFE_INTEGER` are serialized through a hex-placeholder round-trip specifically so
  `JSON.stringify` never touches them as a JS `number` (which would lose precision above 2^53).
  Rust's `serde_json::Number` already stores `u64`/`i64` natively (no `f64` conversion, no
  precision loss up to `u64::MAX`), so `MValue::U`/`I` need none of that trick — `Number::from(u)`
  round-trips exactly. Verified in `value.rs`'s
  `u64_full_range_roundtrips_without_precision_loss` test with
  `18446744069414584320` (WIRE_PROTOCOL.md §0 / PLAN.md §8's example) and `u64::MAX`.
- **Struct keys are the numeric TLV context tag as a decimal string**, from `getStructMembers`
  (CONV:602-615: `id` is the field's TLV tag) used by the `ConvKind.Struct` branch (CONV:412-424):
  `result[id] = converted` when `tagBased` is true. Decode is schema-driven
  (`getStructMembersById`, CONV:622-633) with a documented **fallback to wire-field-name lookup**
  for pre-1.3.0 python clients that used to send name-keyed structs (CONV:427-431,
  `getStructMembersByWireFieldName`, CONV:497-521) — that fallback needs a `ClusterModel` too, so
  it is out of scope for `ws-protocol::MValue::from_json`, which requires every struct key to parse
  as a decimal `u8` tag and errors (`ValueError::BadTag`) otherwise. `matter-names` is expected to
  implement the wire-field-name fallback if/when it is needed, using the same generated field
  tables it already has for `device_command`.
- **What this crate deliberately does *not* implement** (all require a `ClusterModel`/`ValueModel`
  the protocol crate does not have — see PLAN.md §3's "everything HA-shaped ... lives in
  `ws-protocol::server`" vs. what actually needs cluster schema): bitmap number <-> named-flags
  conversion (CONV:23-56, 481-511), epoch-s/epoch-us offset conversion (CONV:88-95, 366-368), and
  the pre-1.3.0 struct wire-field-name fallback above. A future schema-aware layer (`matter-names`,
  or the backend itself for epoch attributes it recognizes) can apply these on top of the raw
  `MValue` this crate produces; nothing here blocks that.

## 25. GET /health (measured 2026-09-04, not from source)

matterjs-server answers `GET /health` with a JSON body, not a plain string:

```json
{"version":"1.4.0","node_count":0}
```

Observed against `matter-server` 1.4.0 running from the compiled-Bun image
(`--disable-dashboard --disable-dcl-seed`), idle with no commissioned nodes.
`version` is the server version string; `node_count` is the number of
commissioned nodes.

Our Rust server currently returns the literal `ok`. Nothing in Home Assistant
depends on this body (the container HEALTHCHECK only checks the status code),
but it is a 1:1 gap — see PLAN.md.
