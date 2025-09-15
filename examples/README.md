# rs-matter-examples

### Examples for `rs-matter`

Each example is a separate, standalone binary implementing a specific Matter device.
Look at the code of each example for details.

See [the main README file](../README.md) for more information about `rs-matter`.

### `dimmable-light`

This is an example Matter device that implements the On/Off and LevelControl clusters and their interaction.

#### Build

`cargo build --bin dimmable_light --features avahi`

#### test

When building the application for testing against Matter yaml tests, use the feature `chip-test`.

`cargo xtask itest --target dimmable_light --features chip-test Test_TC_LVL_1_1 Test_TC_LVL_2_1 Test_TC_LVL_2_2 Test_TC_LVL_3_1 Test_TC_LVL_4_1 Test_TC_LVL_5_1 Test_TC_LVL_6_1`