# Initial proof benchmark

This is an initial implementation datapoint, not a production performance claim. It measures one locally generated Orchard v2 shielded spend using the unmodified upstream circuit.

| Item | Measurement |
|---|---:|
| Circuit key construction | 4,727 ms |
| Prove | 2,222 ms |
| Proof verify | 25 ms |
| Proof bytes | 7,264 B |
| Orchard actions in bundle | 2 |
| Peak RSS | Not measured |

Machine: AMD Ryzen 5 7530U, 6 cores / 12 threads, 15.4 GiB RAM, Windows 11 Home Single Language build 26200. Toolchain: Rust/Cargo 1.96.0. Build: Cargo release profile. Backend: `orchard = 0.16.0` (Cargo.lock), Orchard v2 / `FixedPostNu6_2`; transitive Halo 2 backend is pinned by Cargo.lock.

Command: `cargo test --release -p psp-r-protocol actual_shielded_spend_proof_proves_and_verifies -- --nocapture`.

The latest release run reported `keygen_ms=4727 prove_ms=2222 verify_ms=25 actions=2 proof_bytes=7264`; total test time was 7.37 s. The proof verification number excludes the separately untimed spend-authorization and binding-signature checks performed by the SQLite acceptance path. Key construction is circuit setup, not part of each spend. No mobile benchmark, repeated-run distribution, peak RSS, or independent performance reproduction exists yet.
