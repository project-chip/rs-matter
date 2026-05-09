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

"""Test wrapper that strips `--fail-on-skipped` from `sys.argv` before
running the real test script.

Background: CHIP's `scripts/tests/run_python_test.py` unconditionally
prepends `--fail-on-skipped` to the test-script command line
(`run_python_test.py:284`). The matter testing framework parses that
flag into `matter_test_config.fail_on_skipped_tests = True`
(`matter/testing/runner.py:797`), and at end-of-run if any test method
has called `asserts.skip(...)` the runner forces the process exit code
to non-zero (`runner.py:481-482`):

    if matter_test_config.fail_on_skipped_tests and runner.results.skipped:
        ok = False

That's the right default for SDK CI on a known-conformant DUT — a
spurious skip there is almost certainly a bug. But for several upstream
Matter tests it's a problem when the device under test correctly does
*not* implement the optional feature the test is verifying:

  - `TC_CGEN_2_5..2_11` exercise the General Commissioning *Terms and
    Conditions* (TC) feature (Matter 1.4+, `CGEN.S.F00`). rs-matter
    does not implement TC and explicitly excludes the TC commands from
    `AcceptedCommandList` (see `gen_comm.rs`'s
    `with_cmds(except!(CommandId::SetTCAcknowledgements))`). Each of
    these test bodies starts with:

        if not self.check_pics("CGEN.S.F00"):
            asserts.skip('Root endpoint does not support [TC]')
            return

    so on our PICS file (`CGEN.S=1`, no `CGEN.S.F00`) the test bodies
    skip cleanly without running any TC-specific assertions. The
    framework records a Skipped result and `--fail-on-skipped` then
    flips the exit code to 1 — even though nothing went wrong.

The right structural fix is to drop `--fail-on-skipped` from
`run_python_test.py`'s hardcoded args (or make it opt-out). We don't
patch `connectedhomeip` because (a) the rs-matter checkout pins a
specific chip gitref and (b) we previously vendored a modified runner
and decided not to keep that path. This wrapper achieves the same
result by stripping the flag from `sys.argv` before `runpy`-ing the
real test script — small enough to live alongside
`no_pase_setup_class_helper.py` and trivial to retire when chip exposes
a way to disable the flag.

Mechanism: remove every occurrence of `--fail-on-skipped` from
`sys.argv` (the matter framework's argparser is `action='store_true'`
and accepts no value, so there is nothing else to strip), then `runpy`
the real test script under `__name__ == '__main__'` so its
`default_matter_test_main()` discovers and runs the test classes
normally.

Invocation: the real test script path is passed via the
`RS_MATTER_REAL_TEST_SCRIPT` env var. xtask wires this up in
`python_test_command` for the affected tests (see
`Self::needs_no_fail_on_skipped` in `xtask/src/itest.rs`).
"""

import os
import runpy
import sys

# Strip every `--fail-on-skipped` occurrence from sys.argv. The matter
# argparser registers it with `action="store_true"`, so it consumes no
# following value — we only need to drop the flag itself.
sys.argv = [arg for arg in sys.argv if arg != "--fail-on-skipped"]

real_script = os.environ.get("RS_MATTER_REAL_TEST_SCRIPT")
if not real_script:
    print(
        "RS_MATTER_REAL_TEST_SCRIPT env var is not set (set by xtask)",
        file=sys.stderr,
    )
    sys.exit(2)

# Same `sys.argv[0]` and `sys.path[0]` rewriting as
# `no_pase_setup_class_helper.py` — the framework's debug logging points
# at sys.argv[0], and any sibling helper packages the test imports
# (e.g. `test_testing.*` for the conformance suite) must resolve via
# the script-directory entry that Python normally inserts when running
# a script directly. `runpy.run_path` does not perform that insertion
# automatically.
sys.argv[0] = real_script
sys.path.insert(0, os.path.dirname(os.path.abspath(real_script)))
runpy.run_path(real_script, run_name="__main__")
