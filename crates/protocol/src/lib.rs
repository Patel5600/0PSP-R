//! 0PSP-R protocol boundary.
//!
//! The first proving backend is an unmodified, version-pinned Orchard shielded
//! action circuit. 0PSP-R wraps its proofs in a non-blockchain state machine;
//! it does not claim that a local database provides consensus or operator
//! independence. Custom circuits and legacy V3 encodings are intentionally not
//! accepted here.

pub const PROOF_BACKEND: &str = "zcash/orchard 0.16.0; Halo 2; Orchard v2 circuit";
pub const PROTOCOL_VERSION: u16 = 1;

pub mod capsule;
pub mod ledger;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::ledger::{LedgerError, PrivateLedger, issuance_message, verify_spend};
    use ed25519_dalek::{Signer, SigningKey};
    use incrementalmerkletree::{Hashable, Marking, Retention};
    use orchard::{
        builder::{Builder, BundleType},
        bundle::{BundleVersion, Flags, TxVersion},
        circuit::{OrchardCircuitVersion, ProvingKey},
        keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
        note::ExtractedNoteCommitment,
        tree::{MerkleHashOrchard, MerklePath},
        value::NoteValue,
    };
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use rusqlite::Connection;
    use shardtree::{ShardTree, store::memory::MemoryShardStore};
    use std::time::Instant;

    fn witness(cmx: &ExtractedNoteCommitment) -> (MerkleHashOrchard, MerklePath) {
        let leaf = MerkleHashOrchard::from_cmx(cmx);
        let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
            ShardTree::new(MemoryShardStore::empty(), 100);
        tree.append(
            leaf,
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
        let position = tree.max_leaf_position(None).unwrap().unwrap();
        let path = tree
            .witness_at_checkpoint_id(position, &0)
            .unwrap()
            .unwrap();
        assert_eq!(root, path.root(leaf));
        (root, path.into())
    }

    #[test]
    fn actual_shielded_spend_proof_proves_and_verifies() {
        let mut rng = UnwrapErr(SysRng);
        let version = BundleVersion::orchard_v2();
        let keygen_started = Instant::now();
        let proving_key = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        let keygen_elapsed = keygen_started.elapsed();
        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        // Construct the note through the upstream shielded output builder.
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();
        let mut output =
            Builder::new(BundleType::DEFAULT, version, Flags::SPENDS_DISABLED, anchor).unwrap();
        output
            .add_output(None, recipient, NoteValue::from_raw(23), [0; 512])
            .unwrap();
        let (unproven_output, metadata) = output.build::<i64>(&mut rng).unwrap().unwrap();
        let action_index = metadata.output_action_index(0).unwrap();
        let ivk = fvk.to_ivk(Scope::External);
        let (note, _, _) = unproven_output
            .decrypt_output_with_key(action_index, &ivk)
            .unwrap();

        // Build an authenticated one-leaf witness, then prove a private spend
        // and equal-value replacement output using the actual upstream circuit.
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        let (root, path) = witness(&cmx);
        let mut spend = Builder::new(
            BundleType::DEFAULT,
            version,
            version.default_flags(),
            root.into(),
        )
        .unwrap();
        spend.add_spend(fvk, note, path).unwrap();
        spend
            .add_output(None, recipient, NoteValue::from_raw(23), [0; 512])
            .unwrap();
        let (unauthorized, _) = spend.build::<i64>(&mut rng).unwrap().unwrap();
        let sighash: [u8; 32] = unauthorized.commitment(TxVersion::V5).unwrap().into();
        let proving_started = Instant::now();
        let proven = unauthorized.create_proof(&proving_key, &mut rng).unwrap();
        let proving_elapsed = proving_started.elapsed();
        let authorized = proven
            .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(&sk)])
            .unwrap();
        let verifying_key = proving_key.verifying_key();
        let verifying_started = Instant::now();
        assert!(authorized.verify_proof(&verifying_key).is_ok());
        let verifying_elapsed = verifying_started.elapsed();
        eprintln!(
            "orchard_v2_spend keygen_ms={} prove_ms={} verify_ms={} actions={} proof_bytes={}",
            keygen_elapsed.as_millis(),
            proving_elapsed.as_millis(),
            verifying_elapsed.as_millis(),
            authorized.actions().len(),
            authorized.authorization().proof().as_ref().len(),
        );

        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("ledger.sqlite3");
        let verified = verify_spend(&authorized, &verifying_key, TxVersion::V5).unwrap();
        let issuer = SigningKey::from_bytes(&[42; 32]);
        let issuer_auth = issuer.sign(&issuance_message(&cmx.to_bytes())).to_bytes();
        {
            let ledger =
                PrivateLedger::open_with_issuer(&database_path, Some(issuer.verifying_key()))
                    .unwrap();
            let stale_instance =
                PrivateLedger::open_with_issuer(&database_path, Some(issuer.verifying_key()))
                    .unwrap();
            assert!(matches!(
                ledger.apply(&verified),
                Err(LedgerError::UnknownAnchor)
            ));
            let wrong_auth = issuer.sign(&issuance_message(&[99; 32])).to_bytes();
            assert!(matches!(
                ledger.issue_commitment(cmx.to_bytes(), wrong_auth),
                Err(LedgerError::InvalidIssuanceAuthorization)
            ));
            let ledger_root = ledger
                .issue_commitment(cmx.to_bytes(), issuer_auth)
                .unwrap();
            assert_eq!(ledger_root, root.to_bytes());
            assert!(matches!(
                ledger.issue_commitment(cmx.to_bytes(), issuer_auth),
                Err(LedgerError::DuplicateCommitment)
            ));
            stale_instance.apply(&verified).unwrap();
        }
        let ledger =
            PrivateLedger::open_with_issuer(&database_path, Some(issuer.verifying_key())).unwrap();
        assert!(matches!(
            ledger.apply(&verified),
            Err(LedgerError::DuplicateNullifier)
        ));
    }

    #[test]
    fn startup_rejects_tampered_persisted_root() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("tampered.sqlite3");
        drop(PrivateLedger::open(&database_path).unwrap());

        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute("UPDATE roots SET root = zeroblob(32)", [])
            .unwrap();
        drop(connection);

        assert!(matches!(
            PrivateLedger::open(&database_path),
            Err(LedgerError::CorruptState)
        ));
    }
}
