#!/usr/bin/env -S python3 -B
#
#    Copyright (c) 2024 Project CHIP Authors / rs-matter contributors
#    All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#

"""Test wrapper that disables `BasicCompositionTests.setup_class_helper`'s
PASE leg before running the real test script.

`BasicCompositionTests.setup_class_helper` (in CHIP's
`matter/testing/basic_composition.py`) races an `EstablishPASESession`
against a `GetConnectedDevice` (CASE) and uses whichever returns first.
That race is the source of two distinct failure modes when the test
framework runs against a recently-commissioned rs-matter DUT:

1.  *No BlueZ active* (default on most dev hosts that don't have BT
    hardware). The PASE leg's discovery iterates BLE → Wi-Fi PAF → mDNS
    internally; D-Bus blocks for ~25 s waiting on `org.bluez` activation
    that systemd refuses (the bluetooth.service unit has
    `ConditionPathIsDirectory=/sys/class/bluetooth`, which fails when no
    `bluetooth` kernel module is loaded). Python-side `task.cancel()`
    doesn't interrupt the C++ controller thread that's doing the BLE init.
    By the time the unexpected PASE-completion callback fires (after BLE
    finally times out and mDNS finds the device), the CASE session is
    corrupted and the test body sees `CHIP Error 0x00000048: Not connected`.

2.  *BlueZ active* (e.g. `sudo modprobe bluetooth && sudo systemctl start
    bluetooth` — bluetoothd registers `org.bluez` and reports an empty
    adapter list). BLE init now fails fast, but the PASE leg's discovery
    falls through to mDNS, finds the device, and sends a fresh
    `PBKDFParamRequest`. Our DUT's PASE responder silently drops it because
    the commissioning window is closed (this drop is the behaviour that
    makes `TC_CADMIN_1_5` step 7 produce the spec-expected
    `CHIP_ERROR_TIMEOUT` rather than `CHIP_ERROR_INVALID_PASE_PARAMETER` —
    see `rs-matter/src/sc/pase/responder.rs:109-113`). The controller then
    leaks a "device being commissioned" entry: `mDeviceInPASEEstablishment`
    in `CHIPDeviceController.cpp` is set at the start of the PASE attempt
    and is *not* cleared on the silent-timeout path (the same controller
    lifecycle bug that gates `TC_CADMIN_1_5` step 15 in our list — see the
    `TC_CADMIN_1_5` comment in `xtask/src/itest.rs`). The next
    `dev_ctrl.GetConnectedDevice(allowPASE=True)` — implicit in
    `dev_ctrl.ReadAttribute` — returns that stale "in-progress PASE"
    proxy, the test body logs "Using PASE connection", and the read then
    fails with `CHIP Error 0x00000048: Not connected`.

So neither merely "running BlueZ" nor merely "having a BT adapter" is
enough; the inherent fragility is the PASE+CASE race in setup_class_helper
combined with our spec-correct silent-drop of closed-window PASE attempts.
Two upstream tests already opt out by calling `setup_class_helper(False)`
explicitly — `TC_pics_checker.py` and `TC_IDM_2_2.py`. The remaining
`BasicCompositionTests`-derived tests that matter to us
(`TC_AccessChecker`, `TC_DeviceBasicComposition`, `TC_DeviceConformance`)
call `setup_class_helper()` with the default `allow_pase=True` and trip
one of the two failure modes above.

Upstream has already fixed this on `master` (CHIP commit `b180d46945`,
"Python testing: move setup code function to base (#41712)", landed
2025-12-08): the PASE leg now uses `FindOrEstablishPASESession` instead of
`EstablishPASESession`, so a session that's still alive from the
just-completed commissioning is reused rather than re-attempted against a
closed comm window. That fix is also in `v1.6-sve-branch` but has *not*
been cherry-picked to `v1.5-branch` (our checkout) — which is why nobody
in upstream CI has been hitting this: most CI runs against `master`. The
PR is too entangled to cherry-pick cleanly (it also refactors
`BasicCompositionTests` to inherit from `MatterBaseTest` across ten
files), so for the duration of our `v1.5-branch` checkout we keep this
local shim. Drop it (and the `Self::needs_no_pase_shim` plumbing in
`xtask/src/itest.rs`) once we move to a chip gitref that includes #41712.

Mechanism: this wrapper flips the `setup_class_helper` `allow_pase`
default to `False` for the lifetime of the Python process and `runpy`s
the real test script under `__name__ == '__main__'` so its
`default_matter_test_main()` discovers and runs the test classes
normally.

Invocation: the real test script path is passed via the
`RS_MATTER_REAL_TEST_SCRIPT` env var. xtask wires this up in
`python_test_command` for the affected tests.
"""

import os
import runpy
import sys

# Apply the monkey-patch BEFORE the test module is imported, so its
# `BasicCompositionTests.setup_class_helper` calls (with no `allow_pase`
# argument) use our overridden default.
from matter.testing.basic_composition import BasicCompositionTests  # noqa: E402

_orig_setup_class_helper = BasicCompositionTests.setup_class_helper


async def _setup_class_helper_no_pase(self, allow_pase: bool = False):
    """Same signature as upstream's `setup_class_helper`, but with the
    `allow_pase` default flipped to `False`. Callers that *want* PASE may
    still opt in by passing `allow_pase=True` explicitly."""
    return await _orig_setup_class_helper(self, allow_pase=allow_pase)


BasicCompositionTests.setup_class_helper = _setup_class_helper_no_pase

# Run the real test script as `__main__`. Without rewriting `sys.argv[0]`
# the framework's debug output would point at this wrapper instead of the
# real script, so we patch that up too.
real_script = os.environ.get("RS_MATTER_REAL_TEST_SCRIPT")
if not real_script:
    print(
        "RS_MATTER_REAL_TEST_SCRIPT env var is not set (set by xtask)",
        file=sys.stderr,
    )
    sys.exit(2)

sys.argv[0] = real_script
runpy.run_path(real_script, run_name="__main__")
