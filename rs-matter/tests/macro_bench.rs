//! This module contains tests for the `rs-matter-macros` crate, specifically focusing on macro benchmarks.

#[test]
fn test_timings() {
    let t = trybuild::TestCases::new();
    t.pass("tests/macro_bench/*.rs");
}
