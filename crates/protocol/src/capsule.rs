//! Fixed-size Pocket Seal capsule framing and coarse epoch policy.
//!
//! This module deliberately does not implement encryption. `sealed_blob` is
//! opaque bytes supplied by a future reviewed AEAD layer. Fixed-size framing
//! alone does not make real and cover traffic indistinguishable.

use std::fmt;

pub const CAPSULE_VERSION: u8 = 1;
pub const CAPSULE_SIZE: usize = 50 * 1024;
pub const ROUTING_HEADER_SIZE: usize = 16;
pub const FIXED_HEADER_SIZE: usize = 1 + 8 + ROUTING_HEADER_SIZE;
pub const SEALED_BLOB_SIZE: usize = CAPSULE_SIZE - FIXED_HEADER_SIZE;

/// Version 1 is exactly 50 KiB on the wire. Epoch and routing header are
/// public; payload semantics and encryption are intentionally outside this
/// framing type.
#[derive(Clone, PartialEq, Eq)]
pub struct Capsule {
    epoch_id: u64,
    routing_header: [u8; ROUTING_HEADER_SIZE],
    sealed_blob: Vec<u8>,
}

impl Capsule {
    /// Construct a capsule from an already sealed, fixed-size opaque blob.
    pub fn new(
        epoch_id: u64,
        routing_header: [u8; ROUTING_HEADER_SIZE],
        sealed_blob: Vec<u8>,
    ) -> Result<Self, CapsuleError> {
        if sealed_blob.len() != SEALED_BLOB_SIZE {
            return Err(CapsuleError::WrongBlobLength {
                expected: SEALED_BLOB_SIZE,
                actual: sealed_blob.len(),
            });
        }
        Ok(Self {
            epoch_id,
            routing_header,
            sealed_blob,
        })
    }

    pub fn epoch_id(&self) -> u64 {
        self.epoch_id
    }

    pub fn routing_header(&self) -> &[u8; ROUTING_HEADER_SIZE] {
        &self.routing_header
    }

    /// Return the opaque sealed bytes. This method does not decrypt them.
    pub fn sealed_blob(&self) -> &[u8] {
        &self.sealed_blob
    }

    /// Serialize to the exact version-1 wire length.
    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(CAPSULE_SIZE);
        wire.push(CAPSULE_VERSION);
        wire.extend_from_slice(&self.epoch_id.to_le_bytes());
        wire.extend_from_slice(&self.routing_header);
        wire.extend_from_slice(&self.sealed_blob);
        debug_assert_eq!(wire.len(), CAPSULE_SIZE);
        wire
    }

    /// Parse only the framing. Authentication/decryption belongs to a future
    /// AEAD implementation and must happen before interpreting inner payloads.
    pub fn decode(wire: &[u8]) -> Result<Self, CapsuleError> {
        if wire.len() != CAPSULE_SIZE {
            return Err(CapsuleError::WrongCapsuleLength {
                expected: CAPSULE_SIZE,
                actual: wire.len(),
            });
        }
        if wire[0] != CAPSULE_VERSION {
            return Err(CapsuleError::UnsupportedVersion(wire[0]));
        }

        let epoch_bytes: [u8; 8] = wire[1..9]
            .try_into()
            .map_err(|_| CapsuleError::MalformedHeader)?;
        let routing_header: [u8; ROUTING_HEADER_SIZE] = wire[9..FIXED_HEADER_SIZE]
            .try_into()
            .map_err(|_| CapsuleError::MalformedHeader)?;
        let sealed_blob = wire[FIXED_HEADER_SIZE..].to_vec();

        Self::new(u64::from_le_bytes(epoch_bytes), routing_header, sealed_blob)
    }
}

impl fmt::Debug for Capsule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Capsule")
            .field("version", &CAPSULE_VERSION)
            .field("epoch_id", &self.epoch_id)
            .field("routing_header_len", &self.routing_header.len())
            .field("sealed_blob_len", &self.sealed_blob.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochPolicy {
    /// Oldest accepted capsule age, measured in epoch buckets.
    pub max_age_epochs: u64,
    /// Allowed clock skew into future epochs.
    pub max_future_skew_epochs: u64,
}

impl EpochPolicy {
    pub fn validate(
        self,
        capsule_epoch: u64,
        current_epoch: u64,
    ) -> Result<(), EpochError> {
        let latest_allowed = current_epoch.saturating_add(self.max_future_skew_epochs);
        if capsule_epoch > latest_allowed {
            return Err(EpochError::TooFarInFuture {
                capsule_epoch,
                latest_allowed,
            });
        }
        if current_epoch > capsule_epoch {
            let age = current_epoch - capsule_epoch;
            if age > self.max_age_epochs {
                return Err(EpochError::TooOld {
                    capsule_epoch,
                    current_epoch,
                    max_age_epochs: self.max_age_epochs,
                });
            }
        }
        Ok(())
    }
}

/// Convert Unix seconds to a coarse epoch bucket. A zero duration is invalid.
pub fn epoch_id(unix_seconds: u64, epoch_len_seconds: u64) -> Result<u64, EpochError> {
    if epoch_len_seconds == 0 {
        return Err(EpochError::ZeroEpochLength);
    }
    Ok(unix_seconds / epoch_len_seconds)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleError {
    WrongCapsuleLength { expected: usize, actual: usize },
    WrongBlobLength { expected: usize, actual: usize },
    UnsupportedVersion(u8),
    MalformedHeader,
}

impl fmt::Display for CapsuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongCapsuleLength { expected, actual } => {
                write!(formatter, "capsule length {actual}; expected {expected}")
            }
            Self::WrongBlobLength { expected, actual } => {
                write!(formatter, "sealed blob length {actual}; expected {expected}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported capsule version {version}")
            }
            Self::MalformedHeader => write!(formatter, "malformed capsule header"),
        }
    }
}

impl std::error::Error for CapsuleError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochError {
    ZeroEpochLength,
    TooOld {
        capsule_epoch: u64,
        current_epoch: u64,
        max_age_epochs: u64,
    },
    TooFarInFuture {
        capsule_epoch: u64,
        latest_allowed: u64,
    },
}

impl fmt::Display for EpochError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroEpochLength => write!(formatter, "epoch length must be non-zero"),
            Self::TooOld {
                capsule_epoch,
                current_epoch,
                max_age_epochs,
            } => write!(
                formatter,
                "capsule epoch {capsule_epoch} is too old at {current_epoch} (max age {max_age_epochs})"
            ),
            Self::TooFarInFuture {
                capsule_epoch,
                latest_allowed,
            } => write!(
                formatter,
                "capsule epoch {capsule_epoch} exceeds latest allowed epoch {latest_allowed}"
            ),
        }
    }
}

impl std::error::Error for EpochError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn capsule(epoch_id: u64, fill: u8) -> Capsule {
        Capsule::new(
            epoch_id,
            [0xA5; ROUTING_HEADER_SIZE],
            vec![fill; SEALED_BLOB_SIZE],
        )
        .unwrap()
    }

    #[test]
    fn round_trip_is_exactly_fixed_size() {
        let original = capsule(1_002, 0x31);
        let wire = original.encode();
        assert_eq!(wire.len(), CAPSULE_SIZE);
        assert_eq!(Capsule::decode(&wire).unwrap(), original);
    }

    #[test]
    fn real_and_cover_payload_slots_have_identical_wire_length() {
        // These are opaque fixtures, not real encrypted spend or cover payloads.
        let real_fixture = capsule(1_002, 0x11).encode();
        let cover_fixture = capsule(1_002, 0xEE).encode();
        assert_ne!(real_fixture, cover_fixture);
        assert_eq!(real_fixture.len(), cover_fixture.len());
        assert_eq!(real_fixture.len(), CAPSULE_SIZE);
    }

    #[test]
    fn rejects_short_long_and_unknown_version_capsules() {
        assert!(matches!(
            Capsule::decode(&vec![0; CAPSULE_SIZE - 1]),
            Err(CapsuleError::WrongCapsuleLength { .. })
        ));
        assert!(matches!(
            Capsule::decode(&vec![0; CAPSULE_SIZE + 1]),
            Err(CapsuleError::WrongCapsuleLength { .. })
        ));
        let mut unknown = capsule(0, 0).encode();
        unknown[0] = CAPSULE_VERSION + 1;
        assert_eq!(
            Capsule::decode(&unknown),
            Err(CapsuleError::UnsupportedVersion(CAPSULE_VERSION + 1))
        );
    }

    #[test]
    fn rejects_non_fixed_blob_size() {
        assert!(matches!(
            Capsule::new(0, [0; ROUTING_HEADER_SIZE], vec![0; SEALED_BLOB_SIZE - 1]),
            Err(CapsuleError::WrongBlobLength { .. })
        ));
    }

    #[test]
    fn epoch_uses_floor_and_rejects_zero_length() {
        assert_eq!(epoch_id(0, 600).unwrap(), 0);
        assert_eq!(epoch_id(599, 600).unwrap(), 0);
        assert_eq!(epoch_id(600, 600).unwrap(), 1);
        assert_eq!(epoch_id(1_202, 600).unwrap(), 2);
        assert_eq!(epoch_id(u64::MAX, 0), Err(EpochError::ZeroEpochLength));
    }

    #[test]
    fn epoch_policy_enforces_old_and_future_bounds() {
        let policy = EpochPolicy {
            max_age_epochs: 3,
            max_future_skew_epochs: 1,
        };
        assert_eq!(policy.validate(97, 100), Ok(()));
        assert_eq!(policy.validate(101, 100), Ok(()));
        assert!(matches!(
            policy.validate(96, 100),
            Err(EpochError::TooOld { .. })
        ));
        assert!(matches!(
            policy.validate(102, 100),
            Err(EpochError::TooFarInFuture { .. })
        ));
    }

    #[test]
    fn future_bound_saturates_without_overflow() {
        let policy = EpochPolicy {
            max_age_epochs: 0,
            max_future_skew_epochs: u64::MAX,
        };
        assert_eq!(policy.validate(u64::MAX, u64::MAX), Ok(()));
    }
}
