# rs-matter-tests

### Device-under-test drivers for `rs-matter`

Each binary here is a Matter device (or, for `commissioner_tests`, a Matter
controller) driven by the CHIP certification harness via `cargo xtask itest`.

| Binary | Suite | Exercises |
| --- | --- | --- |
| `system_tests` | `--suite system` (default), `--suite ota` | System clusters plus the general Matter protocol, Interaction Model and Secure Channel tests |
| `light_tests` | `--suite light` | On/Off, Level Control and Color Control |
| `scenes_tests` | `--suite scenes` | Scenes Management |
| `camera_tests` | `--suite camera` | The Matter 1.5+ camera clusters |
| `commissioner_tests` | `--suite commissioner` | `rs-matter` as the **commissioner**, driving CHIP's `chip-all-clusters-app` as the device |

The `.pics` file next to each binary declares what that device implements; the
harness hands it to the CHIP runner, and test steps gated on a PICS entry the
device does not claim are skipped. Keep it in sync with the handlers the binary
actually wires up — claiming an attribute or command that is not served turns
into a confusing test failure, or worse, a test that passes without checking
anything.

Run them through `xtask` rather than directly, so the CHIP environment, the
matching `.pics` and the per-test arguments are all set up:

```sh
cargo xtask itest-setup                 # one-off: clone and build the CHIP SDK
cargo xtask itest                       # the default (system) suite
cargo xtask itest --suite light         # a specific suite
cargo xtask itest TestBasicInformation  # a specific test
```
