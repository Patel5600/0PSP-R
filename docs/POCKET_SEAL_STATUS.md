# Pocket Seal implementation status

Pocket Seal is the proposed transport-metadata layer for 0PSP-R. It combines fixed-size capsules, coarse public epochs, regular cover opportunities, and store-and-forward relays. This document separates implemented framing from unimplemented privacy claims.

## Implemented in this change

- Version-1 capsule framing is exactly 50 KiB (51,200 bytes).
- Public header: version byte, little-endian `epoch_id: u64`, and a fixed 16-byte opaque routing header.
- The remaining bytes are an opaque fixed-size `sealed_blob` slot. The codec rejects any wire length other than 50 KiB, unknown versions, and nonconforming blob lengths.
- Epoch conversion is `floor(unix_seconds / epoch_len_seconds)`; a zero epoch duration is rejected.
- `EpochPolicy` rejects capsules older than a configured maximum age and capsules beyond a configured future-clock-skew allowance.
- Tests cover fixed length, codec round trip, invalid framing, epoch boundaries, old/future rejection and integer-overflow-safe future checks.

## Explicitly not implemented

- No AEAD encryption/decryption or key agreement/rotation.
- No authenticated relay routing, HTTP relay, retry policy or delivery acknowledgement.
- No real-spend/cover inner payload encoding or proof that both payload types are computationally indistinguishable.
- No cover scheduler, constant-rate policy, jitter or offline catch-up behavior.
- No ledger API integration enforcing `EpochPolicy` yet; this module provides a tested policy primitive only.
- No Android/mobile integration, viewing-key scanner, compact filters, or PIR.
- No authenticated external finality or anti-rollback checkpoint.

## Privacy and threat-model caveats

The epoch and routing header are public. Epoch bucketing hides exact timestamps only to the extent that other metadata does not re-identify a sender. Fixed-size framing removes wire-length variation within this version but does not hide sender IP, connection timing, relay identity, submission order, or traffic gaps.

Real and cover traffic can only be made harder to distinguish if clients actually send cover at a sufficiently regular shared rate and replace an opportunity with a real capsule instead of creating a spend-correlated burst. A global observer, a unique active client, offline periods, or a malicious relay that selectively delays/drops traffic can defeat or weaken the protection. Do not describe this implementation as providing traffic-analysis resistance until the AEAD, scheduling, relay, and adversarial evaluation layers exist.

The sealed bytes are treated as opaque; the codec itself does not authenticate or encrypt them. Callers must not send sensitive plaintext to relays through this API. No post-quantum security claim is made.

## Initial policy example

With a 600-second epoch, `epoch_id = floor(utc_unix_seconds / 600)`. A deployment could allow a maximum age of 2 epochs and future skew of 0 or 1 epoch, but those values are policy choices and must be justified against clock skew, delivery delay, censorship and replay risks before production. The current module does not select a production policy.
