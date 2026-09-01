# Generating Matter PICS from the rs-matter data model

> Design note. Companion to `matter-th-x86-setup.md`. All figures were measured against
> the CSA master PICS set **`Matter_1_6_Final_PICS_XML_For_RPI.zip`**
> (`Version No:V_50_1.6_final_release`, generated 2026-05-18 from test plans `master 3acc1fe`),
> downloaded from Causeway on 2026-09-01.

## 1. The problem

The master PICS set is a questionnaire of **2806 boolean items** spanning every cluster in
Matter 1.6. Answering it by hand, against what the firmware actually implements, is slow and
— far worse — silently error-prone. An over-claim does not fail loudly; it enrolls you in
test cases your device cannot pass, or produces a vacuous pass. We have already found three
such over-claims in `tests/src/bin/system_tests.pics` (`MCORE.DD.NFC`, and both
`CUSTOM_COMM_FLOW` / `USER_INTENT_COMM_FLOW`), each of which survived precisely because
nothing exercised them.

rs-matter is unusually well placed to automate this, because its runtime `Node` carries
exactly the metadata the questionnaire asks about — and carries it *as narrowed by the
application*, not as the spec defines it.

## 2. Facts about the master set (verified, not assumed)

| Fact | Detail |
| --- | --- |
| Files | 126: **125 `clusterPICS`** + **1 `generalPICS`** (`Base.xml`, 132 `MCORE.*` items) |
| `<clusterId>` | **Empty in all 125 files** (`<clusterId> </clusterId>`). Cluster identity must come from the item-number prefix, not this field. |
| Pre-filled answers | The templates are **not blank forms**. `<support>` ships pre-answered, overwhelmingly `true` (~2473 `true` vs ~358 `false`). **Uploading them unmodified claims almost all of Matter 1.6.** |
| PIXITs | **129 `<pixitItem>` entries in a separate `<pixit>` section** — a different element. They hold *values* (`yes`, `n/a`, `0x00`), not booleans. The TH's parser iterates `root.iter("picsItem")` and never sees them; PIXITs belong in the TH project config's `test_parameters`. |
| Item shape | `itemNumber`, `feature` (the question text), `reference` (spec section), `status` (with `cond="..."` for conditionals), `support`. |
| Schema | `xsi:noNamespaceSchemaLocation="Generic-PICS-XML-Schema.xsd"` — the schema itself is **not** shipped in the ZIP. |

### Naming conventions (confirmed against `On-Off Cluster Test Plan.xml`)

```
OO.S                cluster as server          OO.S.A4000     attribute (4 hex digits)
OO.C                cluster as client          OO.S.C40.Rsp   command received by server
OO.S.F02            feature bit                OO.C.C40.Tx    command sent by client
OO.M.ManuallyControlled   manual behaviour     PIXIT.OO.ENDPOINT   PIXIT value
```

**Feature bits are hex-indexed** — `DRLK.S.F0a` … `F0e` exist. A classifier using `F[0-9]{2}`
misfiles them as non-derivable. Use `F[0-9a-fA-F]{2}`.

## 3. What is derivable from `Node`

| PICS pattern | Source in the data model |
| --- | --- |
| `XX.S` | cluster present in `Endpoint.clusters` |
| `XX.C` | cluster id present in `Endpoint.client_clusters` |
| `XX.S.A<4hex>` | `Cluster.attributes` (the full spec set) filtered through `with_attrs` |
| `XX.S.C<2hex>.Rsp` | `Cluster.commands` filtered through `with_cmds` |
| `XX.C.C<2hex>.Tx` | client commands / `Command.resp_id` |
| `XX.S.F<2hex>` | bit *n* of `Cluster.feature_map` |
| `XX.S.E<2hex>` | `Cluster.events` filtered through `with_events` |

The decisive property: `attributes` / `commands` / `events` hold **everything the spec
defines**, while `with_attrs` / `with_cmds` / `with_events` are predicates saying which ones
*this instantiation actually serves*. That is precisely the PICS question, already modelled
item by item. It is also the same data the device advertises through Descriptor — so the
PICS is derived from the exact source of truth the Test Harness interrogates.

**Codegen and the IDL are not involved.** `rs-matter-codegen` emits both handler traits and
the `FULL_CLUSTER` metadata const, but `FULL_CLUSTER` is the *spec-complete* set. Only the
runtime `Node` reflects the application's actual composition — endpoints, narrowing
predicates, configured feature map, client clusters.

## 4. The funnel

```
2806   PICS items in the Matter 1.6 master set
2520   derivable from `Node`                                        (90%)
 284   not derivable
 147   ...of which apply to clusters this DUT actually serves
 102   ...auto-fillable from rs-matter knowledge + Node
  45   ...genuinely need a human   ->  8 questions
```

The biggest lever is not inference, it is **filtering by clusters present in `Node`**. Of the
152 manual (`.M.`) items in the set, only **15** sit on clusters `light_tests` serves; the
rest are `RVCOPSTATE` (32), `SEAR` (13), `DRLK` (13), `OVENOPSTATE` (8), `DISHALM` (7) and so
on — moot for a light.

## 5. Tiering

**Tier A — derived from `Node`** (2520 items). Pure function of the data model.

**Tier B — rs-matter library facts** (102 items for this DUT). Split by where the answer lives:

| n | Source | Examples |
| --- | --- | --- |
| 34 | does the app act as an IM client (`client_clusters` non-empty) | `MCORE.IDM.C.*` |
| 26 | cluster / device-type presence in `Node` | `MCORE.OTA.Requestor`, `MCORE.DLOG.*`, `MCORE.BDX.*`, `MCORE.BRIDGE*`, `MCORE.DEVLIST.*`, `MCORE.G.MULTIENDPOINT`, `MCORE.FS` |
| 22 | rs-matter's mDNS implementation — which TXT keys it advertises | `MCORE.SC.*_KEY`, `MCORE.DD.TXT_KEY_*`, `*_SUBTYPE` |
| 12 | commissioner-side questions — `false` for a pure device | `DD.SCAN_QR_CODE`, `DD.QR_COMMISSIONING`, `DD.CTRL_CONCATENATED_QR_CODE_*` |
| 6 | rs-matter's onboarding payload | `*_COMM_FLOW`, `DD.QR`, `DD.MANUAL_PC` |
| 2 | rs-matter's IM server | `IDM.S.LargeData`, `IDM.S.PersistentSubscription` (feature-gated) |

Rows 3, 5 and 6 are **library constants** — identical for every rs-matter device. They belong
in a small curated table shipped with the tool, written once by reading rs-matter's mDNS and
onboarding code, not re-answered per product.

**Tier C — high-level questions** (45 items, 8 questions):

1. Which transports? eth / wifi-2.4 / wifi-5 / thread / ble → 7 (`MCORE.COM.*`)
2. Is the DUT also a commissioner or controller? → 3 (`MCORE.ROLE.*`), and gates Tier B's 12
3. Does the product have a UI / audio interface? → 3 (`MCORE.DD.UI`, `CADMIN.C.M.*`)
4. Does it carry an NFC tag with the onboarding payload? → 2 (`DD.NFC`, `DD.NTL`)
5. Which temperature units / hour formats? → 5 (`LUNIT.*`, `LTIME.*`)
6. Can you induce power-source faults? → 3 (`PS.S.M.*`)
7. OTA behaviours — consent / resume / retry / HTTPS / vendor-specific → 4
8. Misc product facts → 18 (physical control of OnOff, runtime config change, variable-rate
   level, physical tampering, non-concurrent connection, software-component, `PLAT.CERT*`)

Questions 5–7 only fire when the relevant cluster is in `Node`, so a simple light answers
roughly **four**.

## 6. Tool shape

Two pieces, keeping XML and `std` out of firmware:

1. **`Node` → JSON dump** from the device, behind a cargo feature or an env-var check at
   startup. `core::fmt`-friendly, no allocation required. The only rs-matter change.
2. **`cargo xtask pics`** — merges that JSON into the official templates.

```sh
cargo xtask pics --templates <dir-or-zip> --node node.json \
                 [--answers answers.toml] --out <dir>
```

The templates are **always supplied on the command line** and never committed — they are
CSA member material. `--answers` keeps Tier C reproducible in CI; prompt interactively when
absent.

Because the templates ship pre-answered, the tool must **overwrite every derivable item**
rather than fill blanks, and must emit a report of what it changed, what it left alone, and
why. Without that report you cannot audit what you are claiming, which defeats the purpose.

A proc-macro / compile-time variant is attractive but not available today: `with_attrs` and
friends are `fn` pointers, not const-evaluable, so the supported set can only be
interrogated at runtime.

## 6a. Verified: what rs-matter's mDNS actually advertises

Read off `rs-matter/src/transport/network/mdns.rs` (`MatterLocalService::service_internal`).
All keys are emitted through a `.filter(|(_, v)| !v.is_empty())`, so several are conditional
on `dev_det`.

**Commissionable — `_matterc._udp`**

| TXT key | Emitted when | PICS |
| --- | --- | --- |
| `D`, `CM` | always | — |
| `VP` | always | `MCORE.SC.VP_KEY`, `MCORE.DD.TXT_KEY_VP` = true |
| `PH` | always — renders the pairing-hint *bitmap*, so `"0"` (non-empty) even with no hint set | `MCORE.SC.PH_KEY`, `TXT_KEY_PH` = true |
| `DN` | `dev_det.device_name` non-empty | `MCORE.SC.DN_KEY`, `TXT_KEY_DN` |
| `PI` | `dev_det.pairing_instruction` non-empty | `MCORE.SC.PI_KEY`, `TXT_KEY_PI` |
| `DT` | `dev_det.device_type.is_some()` | `MCORE.SC.DT_KEY`, `TXT_KEY_DT` |
| `SAI` | `dev_det.sai.is_some()` | `MCORE.SC.SAI_COMM_DISCOVERY_KEY` |
| `SII` | `dev_det.sii.is_some()` | `MCORE.SC.SII_COMM_DISCOVERY_KEY` |
| `T` | `dev_det.tcp_supported` | `MCORE.SC.T_KEY` |
| `ICD` | ICD device only | — |
| **`RI`** | **never emitted** | `MCORE.SC.RI_KEY`, `TXT_KEY_RI` = **false** |

Subtypes: `_L<discr>`, `_S<short>`, `_V<vid>`, `_T<devtype>` (if `device_type`), `_CM`
-> `MCORE.SC.VENDOR_SUBTYPE` / `MCORE.DD.COMMISSIONING_SUBTYPE_V` = true;
`DEVTYPE_SUBTYPE` / `COMMISSIONING_SUBTYPE_T` = true iff `device_type` is set.

**Operational — `_matter._tcp`**: `SAI`, `SII`, `T`, `ICD`; subtype `_I<compressed-fabric>`.
**`SAT` is never emitted** -> `MCORE.SC.SAT_OP_DISCOVERY_KEY` = **false**.

Cross-check: `tests/src/bin/system_tests.pics` already carries `MCORE.SC.RI_KEY=0`, which
agrees with the code.

An earlier draft of this table listed `DN` and `PI` as unconditional. The guard test in
`pics.rs` falsified that on its first run - `TEST_DEV_DET` leaves `pairing_instruction`
empty, so `PI` is filtered out. Which is the argument for having the test at all.

### Why interrogating both service variants is sound

`MatterLocalService::service` builds a record from `dev_det`, the port, the ICD mode and the
variant's *own* fields. It never reads the fabric table or session state - the
`compressed_fabric_id` / `node_id` only get formatted into the instance name and the `_I`
subtype. So a dump can describe the commissionable **and** the operational record at once,
in any commissioning state, using placeholder ids: only key/subtype *presence* is reported,
and no answer depends on those values.

The single live input is `Matter::icd_mode`, which controls the `ICD` TXT key. No PICS item
derives from it today (ICD is covered by `ICDM.*` cluster PICS), but a dump taken at start-up
- before any ICD registration - would report that key absent.

### Design consequence — this is *not* a static table

Six of these answers depend on runtime `dev_det` (`device_type`, `sai`, `sii`,
`tcp_supported`, ICD mode), not on rs-matter as a library. So Tier B's mDNS block cannot be a
constant shipped with the `xtask`; the **device** has to report it, exactly like the `Node`
dump.

Two ways to do that, and they trade off differently:

1. **Derive by calling** — have the dump invoke `MatterLocalService::service()` and report the
   TXT keys and subtypes it genuinely returns. Zero duplication, so it cannot drift and needs
   no guard test. Costs an API change: the dump then needs a `&Matter` and a scratch buffer,
   not just a `&Node`.
2. **Small table + guard test** — restate the rules in `pics.rs` and add a test that builds a
   service and asserts the table matches. Keeps the `NodeJson(&node)` shape, at the price of
   duplicated logic that only a test holds in place.

(1) is the more robust design; (2) is the less invasive one. Deferred pending a decision.

## 7. Open items before implementing

- The 18-item "misc" bucket in Tier C is a first-pass dumping ground. Several belong in
  Tier B with a proper rule (`MCORE.ACL.Administrator` follows from the ACL cluster being
  present; `MCORE.DD.COMM_DISCOVERY` is commissioner-side). Expect the human set to land
  nearer **30 than 45**.
- The Tier B mDNS table needs writing by reading rs-matter's mDNS implementation — which TXT
  keys it genuinely emits, and which are conditional on ICD or extended discovery.
- `Generic-PICS-XML-Schema.xsd` is not in the ZIP. Validate by round-tripping output through
  the CSA PICS Tool rather than against a local schema.
- Cross-check: `tests/src/bin/light_tests.pics` claims `OO.C.AM-READ`, `OO.C.AM-WRITE`,
  `OO.C.AO-READ`, `OO.C.AO-WRITE`, none of which exist in the official 1.6 On-Off template.
  Stale entries from an older test plan; the tool would surface exactly this class of drift.
