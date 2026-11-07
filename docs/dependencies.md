# Dependency pins

* **quiche:** exact crate release `0.30.0` in both applications.
* **BoringSSL:** `google/boringssl` commit `44b3df6f03d85c901767250329c571db405122d5`, selected by `boring-sys` `4.22.0` (pinned directly in both applications). `boring-sys` builds its pinned BoringSSL source and applies its compatibility patches; there is no floating branch dependency.

The exact quiche and `boring-sys` crate versions are declared in manifests. The BoringSSL commit is pinned by the `boring-sys` source revision and repeated in `SPEC.md` for review. CI resolves the remaining Rust transitive dependencies when building.

Builds use `scripts/cargo-pinned.sh`, which clears `BORING_BSSL_*` overrides so a host-local BoringSSL cannot silently replace the pinned source.

## Update procedure

1. Choose a quiche release and inspect its Cargo manifest plus the corresponding `boring-sys` source for the BoringSSL commit and patches.
2. Update the exact quiche dependency and this documented BoringSSL commit together.
3. Regenerate `Cargo.lock`, build from a clean cache, and run `cargo audit`, `cargo deny check`, and the CI kernel matrix.
4. Review upstream security advisories and validate the quiche/BoringSSL ABI before merge. Never replace a commit with a moving branch or tag.
