# 0PSP-R privacy boundary

## Privacy objective

The ledger verifies shielded spends without learning the spent note, its value, or the relation between the consumed note and created note. A ledger-enforced unique nullifier prevents repeated acceptance of the same spend. These properties depend on the exact circuit, proof verifier, and atomic ledger transition.

The proof does not hide all metadata. The authoritative ledger observes public nullifiers, output commitments, roots, proof sizes, acceptance order, and timing. Network peers may observe IP addresses and request patterns. An endpoint that holds note keys or witnesses can reveal them if compromised. No absolute-privacy claim is made.

## Non-blockchain state model

One operator-controlled ledger is authoritative for commitment-tree roots, nullifier uniqueness, and output insertion. Roots are computed from the append-only commitment log; callers cannot register an arbitrary root. The current Orchard tree has the upstream depth and parameters, and the ledger retains the latest 256 recorded roots. SQLite is durable local state, not consensus. The operator can censor requests, restore an old database, or present inconsistent views unless an external witness/checkpoint scheme is added. Clients still need an authenticated channel to the intended ledger operator.

Initial note insertion requires a signature from a configured Ed25519 issuance authority over a domain-separated commitment. This binds an initial commitment to the issuer but does not prove off-ledger asset backing, enforce a supply cap, or prevent the issuer from inflating supply. Spend outputs are appended atomically with the spend transition. Withdrawals and transparent value deltas are rejected by the current pool path.

## Cryptographic boundary

The current implementation calls the unmodified, pinned Orchard v2/Halo 2 circuit. `verify_spend` performs pure proof and authorization verification and returns opaque checked transition data; `PrivateLedger::apply` enforces the anchor window and uniqueness atomically. It is a classical proof system; post-quantum security is not claimed. This does not mean a new 0PSP circuit inherits an audit or security result merely by using Halo 2. Any circuit, encoding, public-input, or verifier change creates a new relation that requires its own analysis and vectors.

Session ratcheting is transport confidentiality and key evolution. It does not enforce value conservation or double-spend prevention. Ledger spends remain valid only through the shielded proof and authoritative state transition.
