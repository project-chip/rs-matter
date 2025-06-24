# rs-matter-macros

### Proc-macros for the Rust implementation of Matter.

* Proc-macros for deriving the `FromTLV` and `ToTLV` traits;
* An `import!` proc-macro for generating Matter clusters' meta-data and handler traits.

NOTE: The macros are re-exported by the `rs-matter` crate which should be used instead of adding a direct dependency on the `rs-matter-macros` crate.

See [the main README file](../README.md) for more information about `rs-matter`.
