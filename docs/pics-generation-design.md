# Generating Matter PICS from the rs-matter data model

## 1. The problem

The master PICS set is a questionnaire of **2806 boolean items** spanning every cluster in
Matter. Answering it by hand, against what the firmware actually implements, is slow and
— far worse — silently error-prone. An over-claim does not fail loudly; it enrolls you in
test cases your device cannot pass, or produces a vacuous pass.

rs-matter can automate this, because its `Node` type carries exactly the metadata the questionnaire asks about.

**NOTE**: In principle, the task is automatable - albeit to a lesser extent - _regardless_ of the concrete Matter
framework used (rs-matter or not), because every Matter device is oblidged to support the Descriptor cluster, 
and this cluster answers the supported attributes, commands and events by the concrete device. 
The CHIP PICS-generator tool automates exactly this way - by interrogating the Descriptor cluster of the device 
at runtime via the Matter protocol itself.

## 2. Facts about the master set

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

## 4. The funnel - with `light_tests` as a concrete Matter Device

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

### Tier A — derived from `Node` (2520 items)

Pure function of the data model.

### Tier B — rs-matter library facts (102 items for `light_tests`)

Split by where the answer lives:

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

### Tier C — high-level questions** (45 items, < 13 questions)

E.g.:
1. Is the DUT also a commissioner or controller? → 3 (`MCORE.ROLE.*`), and gates Tier B's 12
2. Does the product have a UI / audio interface? → 3 (`MCORE.DD.UI`, `CADMIN.C.M.*`)
3. Does it carry an NFC tag with the onboarding payload? → 2 (`DD.NFC`, `DD.NTL`)
4. Which temperature units / hour formats? → 5 (`LUNIT.*`, `LTIME.*`)
5. Can you induce power-source faults? → 3 (`PS.S.M.*`)
6. Misc product facts → 18 (physical control of OnOff, runtime config change, variable-rate
   level, physical tampering, non-concurrent connection, software-component, `PLAT.CERT*`)

## 6. Tool shape

Two pieces, keeping XML and `std` out of firmware:

1. **`Node` → JSON dump** from the device, behind a cargo feature or an env-var check at
   startup. `core::fmt`-friendly, no allocation required. The only rs-matter change.
2. **`cargo xtask pics`** — merges that JSON into the official templates.

```sh
cargo xtask pics --templates <dir-or-zip> node.json --out <dir-or-zip>
```

The templates are **always supplied on the command line** and never committed — **they are
CSA member material**. `--answers` keeps Tier C reproducible in CI; prompt interactively when
absent.

Because the templates ship pre-answered, the tool must **overwrite every derivable item**
rather than fill blanks, and must emit a report of what it changed, what it left alone, and
why. Without that report you cannot audit what you are claiming, which defeats the purpose.

**NOTE**: A proc-macro / compile-time variant is attractive but not available today:
`with_attrs` and friends are `fn` pointers, not const-evaluable, so the supported set can only be
interrogated at runtime.
