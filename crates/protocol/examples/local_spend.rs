//! Local test-value walkthrough: issuer-signed note -> Orchard proof -> ledger
//! acceptance -> replay rejection. The deterministic issuer key is for this
//! example only and must never be used with real value.

use std::time::Instant;
use std::{error::Error, io};

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
use psp_r_protocol::ledger::{PrivateLedger, issuance_message, verify_spend};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use shardtree::{ShardTree, store::memory::MemoryShardStore};

fn path_for(
    cmx: &ExtractedNoteCommitment,
) -> Result<(MerkleHashOrchard, MerklePath), Box<dyn Error>> {
    let leaf = MerkleHashOrchard::from_cmx(cmx);
    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
        ShardTree::new(MemoryShardStore::empty(), 8);
    tree.append(
        leaf,
        Retention::Checkpoint {
            id: 0,
            marking: Marking::Marked,
        },
    )
    .map_err(|error| {
        io::Error::other(format!(
            "fresh Merkle tree rejected its first leaf: {error:?}"
        ))
    })?;
    let root = tree
        .root_at_checkpoint_id(&0)
        .map_err(|_| io::Error::other("Merkle checkpoint lookup failed"))?
        .ok_or_else(|| io::Error::other("Merkle checkpoint root is missing"))?;
    let position = tree
        .max_leaf_position(None)
        .map_err(|_| io::Error::other("Merkle position lookup failed"))?
        .ok_or_else(|| io::Error::other("Merkle leaf is missing"))?;
    let path = tree
        .witness_at_checkpoint_id(position, &0)
        .map_err(|_| io::Error::other("Merkle witness lookup failed"))?
        .ok_or_else(|| io::Error::other("Merkle witness is missing"))?;
    if root != path.root(leaf) {
        return Err(io::Error::other("Merkle witness root mismatch").into());
    }
    Ok((root, path.into()))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = UnwrapErr(SysRng);
    let version = BundleVersion::orchard_v2();
    let spend_key = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32]))
        .ok_or_else(|| io::Error::other("invalid fixed test spending key"))?;
    let full_viewing_key = FullViewingKey::from(&spend_key);
    let recipient = full_viewing_key.address_at(0u32, Scope::External);
    let empty_root = MerkleHashOrchard::empty_root(32.into()).into();

    let mut note_builder = Builder::new(
        BundleType::DEFAULT,
        version,
        Flags::SPENDS_DISABLED,
        empty_root,
    )?;
    note_builder.add_output(None, recipient, NoteValue::from_raw(23), [0; 512])?;
    let (unproven_note, output_metadata) = note_builder
        .build::<i64>(&mut rng)?
        .ok_or_else(|| io::Error::other("note builder produced no output"))?;
    let output_action = output_metadata
        .output_action_index(0)
        .ok_or_else(|| io::Error::other("output action is missing"))?;
    let ivk = full_viewing_key.to_ivk(Scope::External);
    let (note, _, _) = unproven_note
        .decrypt_output_with_key(output_action, &ivk)
        .ok_or("output note could not be decrypted with recipient key")?;
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    let (anchor, merkle_path) = path_for(&cmx)?;

    // Local deterministic issuance authority for test value only.
    let issuer = SigningKey::from_bytes(&[42; 32]);
    let issuance_auth = issuer.sign(&issuance_message(&cmx.to_bytes())).to_bytes();
    let directory = tempfile::tempdir()?;
    let ledger = PrivateLedger::open_with_issuer(
        directory.path().join("ledger.sqlite3"),
        Some(issuer.verifying_key()),
    )?;
    let issued_root = ledger.issue_commitment(cmx.to_bytes(), issuance_auth)?;
    if issued_root != anchor.to_bytes() {
        return Err(io::Error::other("wallet witness root differs from ledger root").into());
    }

    let mut spend_builder = Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        anchor.into(),
    )?;
    spend_builder.add_spend(full_viewing_key, note, merkle_path)?;
    spend_builder.add_output(None, recipient, NoteValue::from_raw(23), [0; 512])?;
    let (unproven_spend, _) = spend_builder
        .build::<i64>(&mut rng)?
        .ok_or_else(|| io::Error::other("spend builder produced no bundle"))?;
    let sighash: [u8; 32] = unproven_spend.commitment(TxVersion::V5)?.into();
    let proving_key = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let proving_started = Instant::now();
    let proof = unproven_spend.create_proof(&proving_key, &mut rng)?;
    let prove_ms = proving_started.elapsed().as_millis();
    let authorized =
        proof.apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(&spend_key)])?;

    let verify_started = Instant::now();
    let verified = verify_spend(&authorized, &proving_key.verifying_key(), TxVersion::V5)?;
    let verify_ms = verify_started.elapsed().as_millis();
    ledger.apply(&verified)?;
    if ledger.apply(&verified).is_ok() {
        return Err(io::Error::other("replayed spend was accepted").into());
    }

    println!("local test-value spend accepted; replay rejected");
    println!(
        "prove_ms={prove_ms} verify_ms={verify_ms} proof_bytes={}",
        authorized.authorization().proof().as_ref().len()
    );
    Ok(())
}
