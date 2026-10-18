# 0PSP-R

0PSP-R is a private-value protocol project with a **single-authority ledger**, not a blockchain. The privacy target is shielded spends: note ownership, values, and which prior note funds an output are hidden by a zero-knowledge spend proof; a unique nullifier prevents a note from being accepted twice by the authoritative ledger.

"Absolute privacy" is not a cryptographic guarantee. The ledger and network can still observe transaction timing, request metadata, proof sizes, public nullifiers, output commitments, and accepted roots. Endpoint compromise and a malicious ledger operator are outside the proof privacy guarantee.

## Current implementation status

This is an early implementation, **not production-ready**. The proof path uses the upstream Orchard v2 circuit from the version-pinned `orchard` 0.16.0 crate and its Halo 2 backend. The project does not fork or modify that circuit. A real proof-generation/verification test is present. SQLite state transition verifies the bundle and authorization, checks the proof anchor against a commitment tree reconstructed from ledger state, and atomically records nullifiers and output commitments. Replay is rejected across a database reopen.

Not implemented yet: off-ledger backing and supply limits for the configured issuer, an externally authenticated root/finality policy, release key/parameter manifest, ratchet session integration, client workflow, adversarial crash/concurrency suite, mobile benchmarks, and independent audit. The ledger now accepts a commitment only when signed by its configured issuance authority; that authority can still inflate supply, and the signature does not prove external backing. This local ledger is controlled by one operator and does not provide consensus or independent data availability. Do not use real value.

The original `0psp` repository remains separate research. Its custom V3 hash formats and OpenVM proofs are not silently accepted by this protocol.

## Build and test

Requires Rust 1.88 or newer and a C build toolchain for bundled SQLite.

```powershell
cargo test --workspace
```

The shielded spend integration test generates a real proof and can take over a minute in a debug build because it constructs the proving key and proves the statement.

To run the full local test-value flow, including issuer-signed note creation, real Orchard proving and verification, ledger acceptance, and replay rejection:

```powershell
cargo run --release -p psp-r-protocol --example local_spend
```

This example uses deterministic test keys and an unbacked local issuer. It demonstrates the primitive path only; it is not a real-value faucet or deployment configuration.

## Planned modules

- `crates/protocol`: proof verification boundary and non-blockchain state transitions.
- `crates/ratchet`: authenticated session transport, separate from ledger privacy and spend validity.
- `crates/client`: note creation, local proof verification, and ledger submission.

The workspace remains permissively licensed (MIT OR Apache-2.0). Ratchet code is deferred; if added, it will be a clean implementation from the public specification with dedicated review, not copied Signal code. Ratchet encryption does not replace shielded spend proofs.

