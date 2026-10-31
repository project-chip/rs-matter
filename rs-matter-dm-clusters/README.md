# rs-matter-dm-clusters

Native Rust implementation of the Matter (Smart-Home) ecosystem - the clusters generated from the Matter IDL

NOTE: This crate can be used on its own, but to avoid future breakage, prefer depending only on the `rs-matter` crate, which re-exports it. Also, all `rs-matter-*` crates share one version, so the minor version of this crate might change without any breaking changes to it, or without any changes at all.
