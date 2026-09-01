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
cargo xtask pics --templates <dir-or-zip> node.json --out <dir-or-zip>
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
   service and asserts the table matches. Keeps the `write_pics_json(&node, ...)` shape, at the price of
   duplicated logic that only a test holds in place.

(1) is the more robust design; (2) is the less invasive one. Deferred pending a decision.

## 6b. Implemented — measured results

Both halves are in and were run end to end against the real CSA master set.

**Device side** — `rs-matter/src/pics.rs`, cargo feature `pics`:
`Matter::write_pics_json` / `write_mdns_service_pics_json` / `write_node_pics_json`,
`core::fmt`, no allocation. `tests/src/bin/light_tests.rs` gained `--pics-json`,
which dumps and exits before any persistence or networking setup.

```
$ light_tests --pics-json
  4 endpoints, 19 server clusters, 228 supported attributes, 64 received commands
  EP0 dt=22   12 clusters      EP2 dt=259  3 clusters  client_clusters=[6]
  EP1 dt=269   5 clusters      EP3 dt=15   2 clusters
```

**Tool side** — `cargo xtask pics`:

```
cargo xtask pics [OPTIONS] --templates <dir|zip> <NODE>

<NODE>                  the device's data model (positional, required)
--templates <dir|zip>   the CSA master set, as downloaded or unpacked
--out       <dir|zip>   filled XML templates (form chosen by extension)
--pics      <file>      the SDK's flat KEY=1 form, as tests/src/bin/*.pics uses
--baseline  <file>      an existing .pics to lint against and inherit from
--fix                   rewrite --baseline in place with the derived answers
```
Line-oriented rewriting rather than an XML round-trip, so output stays diffable against the
CSA original. Templates always come from the command line and are never committed.

```
Derived 599 answers (267 rewritten, 332 already matching the template)
10 items left untouched:  OO 7   APPDEVICE 1   BINFO 1   LVL 1
22 templates written; all parse; `<pixitItem>` blocks untouched
```

### `--baseline` is a lint on the hand-curated files

Run against `tests/src/bin/light_tests.pics` it reported exactly one disagreement:

```
OO.S.C41.Rsp   claims 0 but the device serves 1
```

`0x41` is `OnWithRecallGlobalScene`, sitting between `C40=1` and `C42=1`. This is an
*under*-claim, and that direction is the more dangerous one: the harness **skips** the gated
steps, so CI stays green for a command the device really serves and never exercises. A lab
would not skip them.

### Flat output

`--pics` emits 554 entries (against 161 hand-curated) in three labelled sections: derived,
not-derivable (values inherited from `--baseline` so nothing such as `PICS_SDK_CI_ONLY` is
silently dropped), and *present in the baseline but absent from the Matter 1.6 templates* -
which is where accumulated drift like `CC.C.AM-READ` surfaces.

The residue is exactly what section 5 predicted: `OO.C.*` (the device *is* an OnOff client,
so which commands it invokes is not modelled), plus three manual `.M.` items.

### The inference that mattered

A first run left **167** items untouched, 76 of them `CC.C.*`. Those are decidable after all:
if a cluster is absent from `client_clusters`, *nothing* on its client surface can be
supported. Adding that rule took the residue from 167 to 10. Only when a cluster **is** a
client does the answer become genuinely unknown - which is why `OO.C.*` survives and
`CC.C.*` does not.

### Worked example of the value

The one change to `On-Off Cluster Test Plan.xml` was a single line:

```diff
-				<support>true</support>     <!-- OO.S.F01, "DeadFrontBehaviour" -->
+				<support>false</support>
```

`light_tests` does not set feature-map bit 1. Shipping the template as downloaded would have
claimed DeadFrontBehaviour and enrolled the device in `TC_OO` steps it cannot pass. That is
the entire argument for this tool, in one line of diff.

## 6c. Lint results across all seven `.pics` files

Every test binary now takes `--pics-json` via `args::dump_pics_json` in
`tests/src/common/args.rs`. For `thread_tests` this required hoisting `Matter::init` above
the Thread attach - the data model depends on neither the operational dataset nor a running
`otbr-agent`, so the dump now works with no Thread environment at all.

| suite | derived | untouched | conflicts | over-claims | under-claims |
| --- | ---: | ---: | ---: | ---: | ---: |
| `light_tests` | 599 | 10 | 1 | 0 | **1** |
| `scenes_tests` | 605 | 4 | 9 | 6 | **3** |
| `camera_tests` | 605 | 4 | 0 | 0 | 0 |
| `system_tests` | 599 | 10 | 251 | 247 | **4** |
| `thread_tests` | 605 | 4 | 0 | 0 | 0 |
| `wireless_tests_wifi` | 605 | 4 | 0 | 0 | 0 |
| `wireless_tests_thread` | 605 | 4 | 0 | 0 | 0 |

Four of the seven are already clean.

### The eight under-claims

The dangerous direction: the harness **skips** the gated steps, so CI stays green for
functionality that is actually shipped.

```
light_tests    OO.S.C41.Rsp     OnWithRecallGlobalScene
scenes_tests   G.S.A0000        Groups NameSupport
               G.S.C05.Rsp      Groups AddGroupIfIdentifying
               OO.S.C41.Rsp
system_tests   BINFO.S.E01      Basic Information event
               BINFO.S.E03      Basic Information event
               CADMIN.S.F00     AdministratorCommissioning "Basic" feature
               DGGEN.S.A000a    GeneralDiagnostics attribute
```

`G.S.C05.Rsp` is `AddGroupIfIdentifying`, which was implemented to replace a `todo!()`
panic; the PICS was never updated, so nothing has exercised it since.

### `system_tests`' 247 over-claims are pre-existing, known debt

**181 of the 251 conflicts sit on clusters the node does not serve at all** - Color Control
(148) and Level Control (26) dominate. That is precisely what the file's own header
anticipates:

> *"Over time, all app clusters need to be turned off, because the `rs-matter` integration
> tests should only test the utility/system clusters..."*

The lint turns "over time" into an enumerated list. The remaining **70 conflicts are on
clusters it does serve** - `OPCREDS` 19, `DGGEN` 10, `DGSW` 8, `CADMIN` 8, `SWTCH` 7,
`CNET` 7 - and those deserve individual review rather than bulk deletion.

### Two inference rules, both found by running it

1. **Client absent** - a cluster missing from `client_clusters` cannot support anything on
   its client surface. Residue 167 -> 10 for `light_tests`.
2. **Server absent** - a cluster the node does not serve cannot support anything on its
   server surface. Residue 141 -> 4 for `camera_tests`, 128 -> 10 for `system_tests`.

Both are sound and neither was obvious from the design; the counts made them visible.

## 6d. The blind spot, and the second pass

The first lint pass reported four of seven `.pics` files "clean". That was **wrong**, and the
reason is worth recording: `PICS_ROOTS` mapped only 19 clusters, and any root outside it was
silently *not derivable* rather than *checked*. Measured per file:

| file | entries | validated | unchecked |
| --- | ---: | ---: | ---: |
| `camera_tests.pics` | 63 | **0** | 63 |
| `thread_tests.pics` | 87 | 24 | 63 |
| `wireless_tests_thread.pics` | 53 | 24 | 29 |
| `wireless_tests_wifi.pics` | 41 | 24 | 17 |
| `scenes_tests.pics` | 129 | 100 | 26 |
| `system_tests.pics` | 794 | 373 | 249 |
| `light_tests.pics` | 162 | 161 | 0 |

`camera_tests` was **0% validated** - its "0 conflicts" meant "nothing was looked at".

Expanding the table to **41 clusters** (each ID confirmed against the served-cluster list the
binaries themselves report) surfaced **87 further conflicts**: `camera_tests` 21,
`system_tests` 65, `thread_tests` 1. Among them four more under-claims:
`PS.S.E00/E01/E02` and `DGTHREAD.S.F03`.

That last one is instructive. An earlier manual pass had deduplicated a conflicting
`DGTHREAD.S.F03=1` / `=0` pair by keeping the last-wins value, `0`. The device serves it, so
the *discarded* value was the correct one. The lint caught a mistake made while hand-fixing
the very file it was checking.

**Totals: 348 corrections across three files; all seven now lint clean.**

## 6e. Trimming dead config

`system_tests.pics` carried app-cluster blocks its suite never exercises. Verified by
resolving **164 of 169** `SYS_TESTS` entries to their YAML/Python sources (the remaining five
are comment fragments, not tests) and extracting every PICS root they reference. Exactly two
of the removal candidates were referenced and kept: `PWRTL` and `MEDIAPLAYBACK`.

```
system_tests.pics:  2402 -> 794 entries,  109 -> 37 roots
                    160 blocks / 1608 entries removed
```

Removed whole blank-line-separated blocks so section comments went with their entries. Every
runner knob survived (`PICS_SDK_CI_ONLY`, `PICS_EVENT_LIST_ENABLED`, `PICS_USER_PROMPT`,
`MCORE.UI.FACTORYRESET`).

The same analysis over the other six files finds **nothing removable**: every root in them is
either served by the device or referenced by its own suite. `system_tests.pics` was the only
one carrying dead weight - which is exactly what its own header had said for years.

## 6f. Coverage reporting

The lesson from 6d - that a "clean" result can mean "nothing was looked at" - is now enforced
by the tool rather than left to discipline. Every `--baseline` run first accounts for all of
its entries:

```
tests/src/bin/light_tests.pics: 138/162 entries checked, 1 out of scope (MCORE/PIXIT/knobs)
    23 not decidable from the data model (manual items / stale keys):
        CC   4    I   3    LVL  5    OO  11
tests/src/bin/light_tests.pics agrees with the data model
```

Entries fall into four buckets, and every one is reported:

1. **checked** - decided from the data model;
2. **out of scope** - `MCORE.*`, `PIXIT.*` and SDK runner knobs, which are not cluster PICS;
3. **not decidable** - the cluster is known but the item is a manual `.M.` behaviour or a key
   no longer present in the templates;
4. **NOT CHECKED** - the cluster is missing from `PICS_ROOTS`, so the entry was skipped
   rather than validated. This one is a `warn!`, names the roots, and says what to do.

Bucket 4 is the failure that produced the false "clean" verdicts. Verified against a
synthetic baseline containing clusters outside the table:

```
fake.pics: 1/4 entries checked, 0 out of scope (MCORE/PIXIT/knobs)
    3 entries NOT CHECKED - cluster missing from PICS_ROOTS ...
        DRLK  2    TSTAT  1
    Add these clusters to `PICS_ROOTS` to close the gap.
fake.pics agrees with the data model
```

Note the last line. "Agrees with the data model" is still printed - but it can no longer be
read without the coverage line directly above it.

Across the seven `.pics` files in this repository, bucket 4 is now **empty**.

## 6g. `PICS_ROOTS` derived for all of Matter 1.6

Hand-maintaining the root->cluster table was the remaining source of blind spots, so it is
now **derived** rather than written. Every `<name>` in the master PICS templates is matched
against the `<name>`/`<code>` pairs in the SDK's ZAP cluster definitions
(`sdk_runner/specifications/chip/*.xml`, 143 clusters).

The table went **41 -> 132 clusters**, and the cross-check is what makes it trustworthy:
**39 of the 41 hand-written entries came back byte-identical**. The two that did not
(`OTAR`, `MEDIAPLAYBACK`) live in *multi-cluster* templates - `Media Cluster Test Plan.xml`
carries `MEDIAPLAYBACK` alongside `CHANNEL`, `MEDIAINPUT` and others - which the
one-root-per-template heuristic cannot resolve; those were mapped by name individually.

### Five roots are deliberately excluded

Listed in `NON_CLUSTER_ROOTS`, because mapping them would produce confidently wrong answers:

| root | what it really is |
| --- | --- |
| `MCORE` | the general, non-cluster PICS (`Base.xml`) |
| `PLAT` | platform certification declarations |
| `ICDB` | ICD *behaviour*; the cluster is `ICDM` |
| `APPDEVICE` | a device-type claim |
| `MC` | "casting video player" - a **device type**, whose sub-items (`MC.S.M.UDC`) are manual |

`MC` is the cautionary one. Name-matching happily mapped it to Media Playback (0x0506),
which would have answered *"does the device implement the casting video player as a server?"*
by looking up an unrelated cluster. Reading the item text caught it.

The coverage report distinguishes these from genuinely unmapped clusters, so the
`NOT CHECKED` warning stays meaningful instead of crying wolf on `APPDEVICE` every run.

### Final state

```
file                          checked   conflicts  NOT CHECKED
light_tests.pics              138/162       0           0
scenes_tests.pics             110/129       0           0
camera_tests.pics              51/63        0           0
system_tests.pics             463/794       0           0
thread_tests.pics              86/87        0           0
wireless_tests_wifi.pics       40/41        0           0
wireless_tests_thread.pics     52/53        0           0
```

Verified that the warning still fires for a genuinely unmapped cluster (`FOO.S` -> one
`NOT CHECKED` entry naming `FOO`).

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
