# Running the Matter Test Harness on x86-64 / Ubuntu 24.04

(Status as of 2026-09-01.)

The CSA Test Harness (TH) is the tool an Authorized Test Lab runs against your device.
Its official install target is a Raspberry Pi. This document covers the **x86-64 route**,
which the TH User Guide calls "TH installation without a Raspberry Pi" (§4.2) and which is
currently rougher than the Pi path.

## 1. Prerequisites

- **Ubuntu 24.04.x LTS** — required, and checked. `scripts/utils.sh::check_ubuntu_os_version`
  hard-compares `lsb_release -sr` against `24.04`. (The guide's `:ubuntu-version:` attribute
  says the same.)
- Docker **< 29.x**. The TH's Traefik proxy breaks on Docker 29; CSA's own
  `scripts/fix-docker-compatibility.sh` detects >= 29 and downgrades. Installing a 28.x
  directly avoids that install-then-rip-out dance.
- Disk: budget generously. The SDK image alone is ~2.6 GB compressed, and building it
  unpacks a full connectedhomeip tree.

**Limitation to understand before you start:** §4.2 states the non-Pi install is for
development and **supports on-network pairing only** — no BLE-WiFi, no BLE-Thread. It is
fine for rehearsing the UI/PICS workflow against an on-network DUT (e.g. rs-matter's own
`tests/src/bin/light_tests` host binary), but a real ESP32 BLE commissioning rehearsal
still needs the Pi.

## 2. Clone

```sh
git clone -b v2.15+spring2026 --recurse-submodules \
  https://github.com/project-chip/certification-tool.git
```

~787 MB with submodules (`backend`, `cli`, `frontend`).

## 3. System dependencies (sudo)

**Do not run `scripts/ubuntu/auto-install.sh` on a general-purpose workstation.** It is
written for a freshly flashed Pi. Specifically it will:

| Step in `auto-install.sh` | Why to skip it on a workstation |
| --- | --- |
| `sudo apt-get upgrade -y` | Full unattended system upgrade of your machine. |
| wpa_supplicant systemd unit on `wlan0` | Writes `/etc/systemd/system/dbus-fi.w1.wpa_supplicant1.service` + `/etc/wpa_supplicant/wpa_supplicant.conf`; fights NetworkManager and can break Wi-Fi. |
| `matter-th.service` enabled at boot | Starts the TH on every boot, and hardcodes `Group=ubuntu`. |
| sysctl `accept_ra` on `eth0`/`wlan0` | Pi interface names; only needed for the Thread/OTBR path. |
| `ip6table_filter` in `/etc/modules` | Only needed for the OTBR container. |
| needrestart config toggling | Only exists to silence prompts during that `apt upgrade`. |
| `ssh-keyscan github.com` | Unnecessary when cloning over HTTPS. |

The equivalent minimal set (steps 1–2 mirror `1.1-install-docker-repository.sh` and
`fix-docker-compatibility.sh`; step 3 merges the two dependency lists):

```sh
# 1. Docker's official apt repository
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y

# 2. Docker engine, pinned below 29.x
DOCKER_VERSION=$(apt-cache madison docker-ce | awk '$3 !~ /^5:29\./ {print $3; exit}')
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
  docker-ce=$DOCKER_VERSION docker-ce-cli=$DOCKER_VERSION \
  containerd.io docker-buildx-plugin docker-compose-plugin
sudo apt-mark hold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 3. TH runtime dependencies
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3-pip python3-venv \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
  libatomic1 libavformat60 libavcodec60 libavutil58 libswresample4 libswscale7 \
  libevent-2.1-7t64 libevent-pthreads-2.1-7t64 libpcsclite1

# 4. Docker group
sudo groupadd -f docker
sudo usermod -aG docker $USER
```

Then log out and back in for the `docker` group to take effect.

Two lasting changes: `apt-mark hold` pins Docker until you `apt-mark unhold` those packages,
and `docker` group membership is effectively root-equivalent.

CSA's Poetry install (`curl -sSL https://install.python-poetry.org | python3 -`) is only
needed for the TH's command-line client; the web UI does not need it.

## 4. Local patches required

### 4.1 The username gate

`scripts/utils.sh::check_user_name` hard-requires `whoami == "ubuntu"` and exits 1 otherwise.
It is called from `check_installation_prerequisites`, which both `internal-auto-install.sh`
and `internal-auto-update.sh` invoke — so **every scripted path refuses to run** unless your
account is literally named `ubuntu`.

Patching this check past is necessary but **not sufficient**: the requirement is real, and
it is enforced a second time, silently, by a hardcoded host path in the backend. See §6.2 —
do not skip it, or you will get a TH that looks healthy and runs zero Python tests.

Minimal reversible fix:

```sh
sed -i 's/if \[ "$USER_NAME" != "ubuntu" \]; then/if [ "$USER_NAME" != "${TH_EXPECTED_USER:-ubuntu}" ]; then/' scripts/utils.sh
# then export TH_EXPECTED_USER=$(whoami) when running their scripts
```

### 4.2 Port 80 is hardcoded

`docker-compose.yml` maps the Traefik proxy as a literal `"80:80"` with no variable, unlike
essentially every other setting. If anything already listens on :80, `start.sh` fails with
`failed to bind host port for 0.0.0.0:80 … address already in use`.

Traefik routes the backend and frontend by `PathPrefix`, **not** by `Host`, so remapping the
host port is safe:

```sh
sed -i 's/^      - "80:80"$/      - "8080:80"/' docker-compose.yml
```

The UI is then at `http://localhost:8080` — **but see §4.3: moving the port also requires a
frontend fix, or the UI loads and every API call fails.**

### 4.3 The frontend drops the port (so the TH is hard-wired to port 80)

`frontend/src/environments/environment.ts` (and `.prod.ts`) build every backend URL from the
**hostname only**:

```js
const hostName = window.location.hostname;      // no port!
restBaseURL:        'http://' + hostName + '/api/v1/',
webSocketBaseURL:   'ws://'   + hostName + '/api/v1/ws',
webRTCWebSocketURL: 'ws://'   + hostName + '/api/v1/ws/webrtc/peer',
streamBaseURL:      'ws://'   + hostName + '/api/v1/ws/video',
```

`window.location.hostname` excludes the port, so served on any port but 80 the app loads its
static assets fine and then sends every REST and WebSocket call to **port 80**. Symptoms in
the browser: *"Failed to connect / something went wrong"*, *"Error Unprocessable Entity"*
(the REST call reaching whatever else owns port 80), and *"WebRTC Connection Error"*.

Fix — use `window.location.host`, which includes the port:

```sh
sed -i 's/window\.location\.hostname/window.location.host/' \
  frontend/src/environments/environment.ts frontend/src/environments/environment.prod.ts
cd frontend && DOCKER_BUILD_VERSION=5be5818 ./scripts/build-docker-image.sh
```

(`environment.prod.ts` declares it as `const hostName: string = ...`, so a sed keyed on the
whole line needs to match both forms. The container runs `ng serve`, i.e. the **dev**
config, so `environment.ts` is the one that actually takes effect.)

This also makes SSH port-forwarding work on an arbitrary local port:

```sh
ssh -L 9090:localhost:8080 user@build-machine    # then http://localhost:9090
```

Without the fix the tunnel must terminate on local port 80, which needs root on the client.

## 5. Container images

`postgres:12` and `traefik:v3.6.1` are multi-arch and pull fine.

**The TH's own backend and frontend images are published for `linux/arm64` only.**
This is a trap: `docker compose pull backend frontend` **appears to succeed** — it pulls the
arm64 images onto an x86-64 host without complaint. The failure surfaces only later, when
the containers exit immediately with:

```
exec /usr/bin/bash: exec format error
```

Verify with `docker image inspect <image> --format '{{.Os}}/{{.Architecture}}'`. On x86-64,
delete them and build locally:

```sh
docker image rm ghcr.io/project-chip/csa-certification-tool-backend:c1c4ed3 \
                ghcr.io/project-chip/csa-certification-tool-frontend:5be5818
./scripts/build.sh
```

`build.sh` tags by the submodule's `git rev-parse --short HEAD`, which yields exactly the
`c1c4ed3` / `5be5818` tags `docker-compose.yml` expects — provided the submodule working
trees are clean (a dirty tree appends `-local` to the tag and compose will not find it).

### 5.1 The backend image also fails to build — unpinned `npm@latest`

`backend/Dockerfile` does:

```dockerfile
RUN curl -sL https://deb.nodesource.com/setup_20.x | bash -   # pins Node 20
RUN apt-get install -y nodejs
RUN npm install -g npm@latest                                  # NOT pinned
RUN npm install -g cspell@latest                               # NOT pinned
```

Node is pinned to 20; npm is not. `npm@latest` is now 12.0.2, which declares
`{"node":"^22.22.2 || ^24.15.0 || >=26.0.0"}`, so the build dies:

```
npm error code EBADENGINE
npm error notsup Not compatible with your version of node/npm: npm@12.0.2
npm error notsup Required: {"node":"^22.22.2 || ^24.15.0 || >=26.0.0"}
npm error notsup Actual:   {"npm":"10.8.2","node":"v20.20.2"}
```

Same failure mode as the `gn` bug in §6: a pinned toolchain paired with an unpinned
`@latest` dependency. Minimal fix, keeping Node 20:

```dockerfile
RUN npm install -g npm@^10
```

(The upstream fix is a choice between pinning npm as above, or moving nodesource to
`setup_22.x`. Note Node 20 already ships npm 10.8.2, so the line is close to a no-op.)

**Tagging caveat when patching:** `build-docker-image.sh` derives the tag from
`git rev-parse --short HEAD` and appends `-local` when `git diff` is non-empty — so a
patched Dockerfile produces `c1c4ed3-local`, which `docker-compose.yml` will not find.
Override it explicitly:

```sh
cd backend  && DOCKER_BUILD_VERSION=c1c4ed3 ./scripts/build-docker-image.sh
cd frontend && DOCKER_BUILD_VERSION=5be5818 ./scripts/build-docker-image.sh
```

(The `DIRTY` variable in that script only gates `--push`, so a dirty tree does not block
the build itself.)

## 6. The SDK image (`chip-cert-bins`) — and an upstream breakage

The TH runs the actual tests inside `connectedhomeip/chip-cert-bins:<SDK_SHA>`. Only
`linux/arm64` is published (verified on Docker Hub for tag `b91b83ff…`), so x86-64 must
build it. The guide estimates ~3 hours.

```sh
SDK=b91b83ffa967e2fffca471fb28c745ae6fd3ec9d
curl -fsSL -o Dockerfile \
  "https://raw.githubusercontent.com/project-chip/connectedhomeip/$SDK/integrations/docker/images/chip-cert-bins/Dockerfile"
docker buildx build --load --build-arg COMMITHASH=$SDK \
  --tag connectedhomeip/chip-cert-bins:$SDK .
```

### This build fails as written — unpinned `gn`

The Dockerfile builds `gn` from an **unpinned** clone:

```dockerfile
RUN set -x \
    && git clone https://gn.googlesource.com/gn \
    && cd gn \
    && python3 build/gen.py \
    && ninja -C out \
    ...
```

Building today produces:

```
../src/gn/err.h:207:46: error: expected unqualified-id
  207 | inline E GetError(std::expected<T, E>&& exp) {
14 errors generated.
```

Traced: gn commit `152bfad2` (**2026-08-10**, *"Implement a Result<T> type."*) introduced
`std::expected` into `src/gn/err.h`, which the image's toolchain will not compile. The SDK
commit CSA pins is from 2026-06-05, when gn's HEAD was `6f8c0328` (2026-06-02) and contained
no `std::expected`.

**So the image was reproducible when CSA published it and is not reproducible now.**

The rot is **temporal, not architectural.** The `gn` step is a plain `RUN` with no
`case $TARGETPLATFORM` guard (unlike the app-build stage, which does branch on arch), so a
from-source **arm64** build today fails identically. Architecture only determines *who is
forced to build from source*: arm64 users pull the image CSA published in June and never
exercise the source path; amd64 has no published image, so amd64 builders are simply the
only ones currently running it. CSA would hit this on their next from-source rebuild of
either arch.

The general shape of both this and the `npm` bug in §5.1: **these images are built once per
release and pulled forever after, so the source path is never re-exercised and unpinned
`@latest` / HEAD dependencies rot silently.**

### Upstream status (checked 2026-08-31)

- `connectedhomeip` **master** and **v1.6-branch** no longer build `gn` from source at all —
  they apt-install Ubuntu's `generate-ninja` package. The bug is already fixed there.
- **v1.5-branch** still carries the unpinned `git clone https://gn.googlesource.com/gn`.
- **However**, the pinned SDK commit `b91b83ff` lives on **`v1.6-sve-branch`** — it is a
  direct ancestor of that branch's head, exactly one commit behind it. SVE =
  *Specification Validation Event*, CSA's pre-certification validation events.

### Why the TH pins an SVE branch and not `v1.6-branch`

This is deliberate and correct. Certification requires every ATL and every vendor to run
**bit-identical test content** — if the TH tracked `v1.6-branch` (which has moved 796 commits
since the fork), your pre-test and the lab's run would execute different scripts. So the
branch is forked, has test/data-model corrections cherry-picked onto it, is qualified, and
is then frozen.

**And that freeze is exactly why the Docker build rots.** 

**Consequence for fixing it:** bumping `SDK_DOCKER_TAG` does **not** help — `v1.6-sve-branch`
HEAD (`c2573a13`, 2026-07-15) still carries the unpinned `git clone .../gn` at line 118, and
the single commit beyond the pin is an unrelated `DataModelRevision` backport. The fix is a
**PR against `v1.6-sve-branch`** — backport the `generate-ninja` change, or add the one-line
`gn` pin — which is exactly the kind of cherry-pick that branch already receives routinely.

Fix — pin gn to the revision contemporary with the SDK commit:

```dockerfile
    && git clone https://gn.googlesource.com/gn \
    && cd gn \
    && git checkout 6f8c0328ee29c76e3566a216f2f0cf2992daa6ed \
    && python3 build/gen.py \
```

Verified: with this pin the gn stage completes (113 s) and the build proceeds.

## 6.1 Startup order: the backend blocks on the SDK image

Once the four containers are up, the **UI answers on `/` but the API returns 502** until the
SDK image exists. This is not a proxy misconfiguration — the backend's ASGI startup hook
blocks trying to launch the SDK container:

```
uvicorn.lifespan.on:startup  | Waiting for application startup.
test_manager:initialize_python_tests   | Initializing Python test collections (async)
test_manager:_generate_all_test_files  | Starting test file generation with shared container session
container_manager:get_container:76     | Did not find container by id or name: th-sdk.
```

So `connectedhomeip/chip-cert-bins:<SDK_SHA>` is a hard prerequisite for a working backend,
not just for running tests. Build it first, or expect to restart the backend afterwards.

Useful readiness probes:

```sh
curl -o /dev/null -w '%{http_code}\n' http://localhost:8080/       # UI (Angular dev server)
curl -o /dev/null -w '%{http_code}\n' http://localhost:8080/docs   # backend API
```

The frontend is an Angular **dev server** that compiles its bundle on first start, so `/`
also 502s for the first couple of minutes. That one resolves on its own.

**Cosmetic note:** a backend built from a patched tree logs
`Test Engine SHA is c1c4ed3-local` even when the image tag was forced with
`DOCKER_BUILD_VERSION`, because the version string is baked in from git state at build time.
Harmless.

## 6.2 The hardcoded `/home/ubuntu` path — silent, and the real reason for the username rule

With the SDK image built and all four containers healthy, the API comes up and reports 385
test cases — but:

```
  SDK YAML Tests:             3 suites, 380 test cases
  Onboarding Payload Tests:   1 suites,   4 test cases
  SDK Performance Tests:      1 suites,   1 test cases
  Mandatory SDK Python Tests: 0 suites,   0 test cases     <-- wrong
  SDK Python Tests:           0 suites,   0 test cases     <-- wrong
```

The YAML suites load, the Python suites are empty, and **nothing logs an error**.

Cause — `backend/test_collections/matter/sdk_tests/support/sdk_container.py:51`:

```python
# Python Testing Folder
LOCAL_TEST_COLLECTIONS_PATH = (
    "/home/ubuntu/certification-tool/backend/test_collections/matter"
)
```

That absolute host path is the bind-mount source for the SDK container's Python test tree,
the RPC client and the stress-test script. It is **not** derived from
`BACKEND_FILEPATH_ON_HOST` (that variable is only read by `otbr_manager.py` and one
endpoint), so setting it correctly — as `start.sh` does — changes nothing here.

The failure is silent because Docker **auto-creates a missing bind source** as an empty
root-owned directory. So the SDK container faithfully mounts
`/home/ubuntu/certification-tool/.../python_testing` — an empty tree Docker just invented —
finds no test scripts, and generates nothing. Verify with:

```sh
find /home/ubuntu -type d      # a skeleton tree that nobody created on purpose
find /home/ubuntu -type f      # zero files
```

**This is the load-bearing reason the TH insists on the `ubuntu` username *and* on the
checkout living at `~/certification-tool`.** The `check_user_name` gate is a proxy for this
constant, not a cosmetic preference.

Fix without relocating the checkout — point the hardcoded path at the real one:

```sh
sudo rm -rf /home/ubuntu/certification-tool          # the empty tree Docker invented
sudo ln -s /path/to/your/certification-tool /home/ubuntu/certification-tool
```

(Patching `sdk_container.py` on the host does **not** work: the backend runs its own copy of
the code from inside the image at `/app`, so a source edit needs an image rebuild or the
`docker-compose.override-backend-dev.yml` dev mount. The symlink is far cheaper.)

Then restart via `./scripts/start.sh` and re-check the collection counts. **Verified fix:**

```
before:  385 test cases   (SDK Python Tests: 0 suites,   0 cases)
after:   839 test cases   (SDK Python Tests: 3 suites, 449 cases)
```

and 457 `TC_*.py` files appear under
`backend/test_collections/matter/sdk_tests/sdk_checkout/python_testing/`.

Note the `th-sdk` container is **started on demand** and stopped again once test generation
finishes, so `docker ps` showing no `th-sdk` is normal, not a fault.

Same mechanism applies to `/var/paa-root-certs` and `/var/credentials/development`
(`sdk_container.py:43,47`) — Docker will happily create those empty too, which is why §7's
`setup.sh` must actually run rather than being assumed.

## 7. Matter program setup

Once the SDK image exists, `backend/test_collections/matter/setup.sh` must run. It needs
sudo and it:

- `apt-get satisfy`s ~20 build packages (`g++`, `gcc`, `ninja-build`, `generate-ninja`,
  `libavahi-client-dev`, `libcairo2-dev`, `libdbus-1-dev`, `libssl-dev`, `npm`, `figlet`,
  `toilet`, …) from `backend/test_collections/matter/scripts/package-dependency-list.txt`;
- runs `update-sample-apps.sh`, which does `sudo docker run … -v ~/apps:/apps
  -v ~/mock_server:/mock_server -v ~/credentials:/credentials` to copy the sample apps and
  development credentials out of the SDK image, **deleting the previous contents of those
  three directories**;
- runs `update-paa-certs.sh`, which does `sudo rm -rf` on `/var/paa-root-certs` and
  `/var/credentials/development`, recreates them and copies the SDK's development PAA certs in.

Expected result: 228 files in `/var/paa-root-certs` (including `Chip-Test-PAA-FFF1-Cert.pem`,
the development PAA that test-credential DUTs chain to), an `attestation` / `cd-certs` /
`commissioner_dut` tree in `/var/credentials/development`, and 35 sample apps in `~/apps`.

### 7.1 What this actually does to your host

Be aware before running it on a machine you care about: **`setup.sh` installed 420 packages**
here. Ubuntu's `npm` pulls in Debian's entire `node-*` constellation (`node-tap`, `node-gyp`,
`node-ws`, `node-yaml`, `nodejs-doc`, …) plus `x11-utils`, `x11-xserver-utils` and `zutty`
(an X terminal emulator).

Grepping the whole TH repo, **none of it is used**: host `npm` appears only in `node -v` /
`npm -v` version echoes in a diagnostics script and in `docker exec <container> npm -v`
(which queries the *container's* npm, not the host's); `figlet` and `toilet` are never
invoked anywhere. The node/npm the TH genuinely needs is installed *inside* the backend
image by `backend/Dockerfile`, which is the correct place for it.

## 8. Known upstream issues (candidates for PRs)

| # | Repo | Issue | Severity |
| --- | --- | --- | --- |
| 1 | `connectedhomeip`, branch **`v1.6-sve-branch`** | The from-source `gn` build is unpinned and no longer compiles (gn `152bfad2`, 2026-08-10, added `std::expected`). Fixed on `master`/`v1.6-branch` via the `generate-ninja` package, but never cherry-picked to the SVE branch the TH pins — and its HEAD is still broken, so bumping the pin does not help. | **High** — blocks the documented x86 install entirely. PR to `v1.6-sve-branch`. |
| 2 | `certification-tool` | `check_user_name` hard-requires the account be named `ubuntu`, blocking every scripted path. Contradicts the guide's own §4.2 non-Pi install. | **High** — trivially fixed by honouring an env var. |
| 3 | `certification-tool` | `docker compose pull` silently fetches arm64 backend/frontend onto amd64; failure only appears as `exec format error` at container start. Should either publish amd64 or fail loudly / auto-build on arch mismatch. | **Medium** |
| 4 | `certification-tool` | Proxy host port hardcoded `"80:80"` in `docker-compose.yml`; no override. Should be `${TH_HTTP_PORT:-80}:80`. | **Medium** |
| 5 | `certification-tool` | User guide §4.2 note says amd64 images "will not always be available" — in practice they are *never* available and the doc should say so plainly, with the `build.sh` step mandatory rather than conditional. | **Low** (docs) |
| 6 | `certification-tool` | `2-machine-cofiguration.sh` — filename typo, and hardcodes `Group=ubuntu` in the systemd unit while parameterising `User=$USER`. | **Low** |
| 7 | `certification-tool` | `backend/Dockerfile` pins Node to 20 via `setup_20.x` but installs unpinned `npm@latest` (and `cspell@latest`). npm 12 requires Node >= 22, so the backend image no longer builds. | **High** — blocks the x86 install, since amd64 backend images are not published. |
| 8 | `certification-tool-backend` | `sdk_tests/support/sdk_container.py:51` hardcodes `/home/ubuntu/certification-tool/...` as a bind-mount source instead of deriving it (e.g. from `BACKEND_FILEPATH_ON_HOST`, which already exists and is set correctly). Docker auto-creates the missing path, so the TH silently loads **zero Python tests** with no error anywhere. | **Critical** — a TH that looks healthy but cannot run the Python certification tests. |
| 9 | `certification-tool-backend` | `test_collections/matter/scripts/package-dependency-list.txt` lists `npm`, `figlet` and `toilet` as host dependencies. None are used anywhere in the repo; `npm` alone drags ~400 transitive packages (incl. X11 and an X terminal emulator) onto the host. | **Low** — pure host pollution, trivial to drop. |
| 10 | `certification-tool-frontend` | `src/environments/environment{,.prod}.ts` derive all REST/WebSocket URLs from `window.location.hostname`, which excludes the port, so the UI only works when served on port 80. Combined with #4 (hardcoded `80:80`) the port is effectively immovable. One-word fix: `window.location.host`. | **Medium** — UI loads but every API/WS call fails, with misleading error toasts. |
| 11 | `certification-tool-backend` | TC-DD-1.1's discriminator prompt says *"enter 12-bit discriminator from the device advertisement"* but parses the answer with `int(response, 16)` (`onboarding_script_support.py:201`). The advertisement's `D=` TXT key is **decimal** per spec, so entering the value actually observed (`3840`) is read as `0x3840` = 14400 and the step fails with a misleading mismatch. Only the placeholder (`0xF00`) hints at hex. TC-DD-1.4 repeats the pattern: its device-*count* prompt is also `int(x, 16)` (placeholder `0x2`), so a 10-device answer of `10` becomes 16. | **Low** — operator trap; prompts should state the base or accept `int(x, 0)`. |
| 12 | environment / `certification-tool` docs | On a Docker host, avahi-daemon registers address records for `docker0`, every `br-*` bridge and every transient `veth*`. The TH starts/stops the `th-sdk` container per test, so Avahi is near-perpetually re-registering; chip logs "Avahi re-register required" and tears down its DNS-SD layer, leaving `DiscoveryImplPlatform::mState != kInitialized`. Every `Advertise`/`RemoveServices`/`FinalizeServiceUpdate`/`ResolveNodeId` then returns `CHIP_ERROR_INCORRECT_STATE` — commissioning completes through 'Cleanup' and is *then* reported as failure. Fix: `allow-interfaces=<nic>` in `/etc/avahi/avahi-daemon.conf`. The x86 guide should say so. | **Critical** — commissioning reported as failing when it actually succeeded. |
| 12b | environment / `certification-tool` docs | **Same symptom as #12, different trigger, and `allow-interfaces=` does not prevent it.** Ubuntu ships systemd-resolved with `MulticastDNS=yes` (`/etc/systemd/resolved.conf`), so it runs a second mDNS responder alongside avahi-daemon. Both publish the host's own A/AAAA records and each treats the other's answer as a conflict, so avahi renames itself every ~20s (`m800` → `m800-2` → … → `m800-359` over one morning), withdrawing and re-registering every address record each time. chip's DNS-SD layer is torn down mid-flight exactly as in #12, but the trigger is a hostname conflict rather than interface churn. Observed on the TH: chip-tool inside `th-sdk` blocks in the commissioning resolve, emits **zero** Matter traffic (0-byte `trace_log_*_CHIP_WEBSOCKET_SERVER.log`), stops servicing its websocket, and the backend fails the suite with `sent 1011 (unexpected error) keepalive ping timeout`; the *next* suite then reports `Unable to start chip server` because the wedged chip-tool still holds port 9002. Diagnose with `journalctl -u avahi-daemon \| grep 'Host name conflict'` — not with the avahi *config*, which looks correct throughout. Fix: `MulticastDNS=no` in `/etc/systemd/resolved.conf`, then restart `systemd-resolved` and `avahi-daemon`. | **Critical** — boot-persistent on a default Ubuntu install; every run fails at 'Commission DUT' with no Matter traffic and a misleading websocket error. |
| 13 | `certification-tool-backend` | `LegacyPythonTestCase.setup()` prompts "Should the DUT be commissioned to run this test case?" for *every* legacy-format test (27 of them in a light DUT's set), and answering NO still triggers a second prompt. Modern tests encode this structurally via suite type. Could be asked once per run. | **Low** — operator toil. |
