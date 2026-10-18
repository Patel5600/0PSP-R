//! Single-authority, non-blockchain state transition for Orchard shielded bundles.
//!
//! Commitment roots are constructed from the append-only ledger commitment log.
//! Callers cannot register arbitrary roots. This is a local state machine, not
//! a consensus or finality mechanism; the operator controls the database.

use std::{collections::VecDeque, path::Path, sync::Mutex, time::Duration};

use ed25519_dalek::{Signature, VerifyingKey as IssuerVerifyingKey};
use incrementalmerkletree::frontier::Frontier;
use orchard::{
    bundle::{Authorized, Bundle, TxVersion},
    circuit::VerifyingKey,
    note::ExtractedNoteCommitment,
    tree::MerkleHashOrchard,
};
use rusqlite::{Connection, TransactionBehavior, params};

const TREE_DEPTH: u8 = 32;
const ANCHOR_WINDOW: usize = 256;
type CommitmentTree = Frontier<MerkleHashOrchard, TREE_DEPTH>;

struct LedgerState {
    connection: Connection,
    frontier: CommitmentTree,
    recent_roots: VecDeque<[u8; 32]>,
    issuer_key: Option<IssuerVerifyingKey>,
}

#[derive(Debug)]
pub enum LedgerError {
    InvalidProof,
    InvalidAuthorization,
    PublicValueBalance,
    UnknownAnchor,
    DuplicateNullifier,
    DuplicateCommitment,
    InvalidCommitment,
    IssuanceDisabled,
    InvalidIssuanceAuthorization,
    CorruptState,
    Storage(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "shielded proof rejected"),
            Self::InvalidAuthorization => write!(f, "authorization rejected"),
            Self::PublicValueBalance => write!(f, "public value balance is not permitted"),
            Self::UnknownAnchor => write!(f, "bundle anchor is outside the ledger anchor window"),
            Self::DuplicateNullifier => write!(f, "nullifier already spent"),
            Self::DuplicateCommitment => write!(f, "output commitment already exists"),
            Self::InvalidCommitment => write!(f, "output commitment encoding is invalid"),
            Self::IssuanceDisabled => write!(f, "no issuance authority is configured"),
            Self::InvalidIssuanceAuthorization => write!(f, "issuance authorization rejected"),
            Self::CorruptState => write!(f, "ledger commitment state is inconsistent"),
            Self::Storage(message) => write!(f, "ledger storage error: {message}"),
        }
    }
}

impl std::error::Error for LedgerError {}

pub struct PrivateLedger {
    state: Mutex<LedgerState>,
}

/// Proof-checked public transition data. Fields are private so callers can only
/// obtain one through [`verify_spend`]; applying it still performs anchor and
/// uniqueness checks against current ledger state.
pub struct VerifiedSpend {
    bundle_id: [u8; 32],
    anchor: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
    outputs: Vec<[u8; 32]>,
}

impl PrivateLedger {
    pub fn in_memory() -> Result<Self, LedgerError> {
        Self::in_memory_with_issuer(None)
    }

    pub fn in_memory_with_issuer(
        issuer_key: Option<IssuerVerifyingKey>,
    ) -> Result<Self, LedgerError> {
        let connection = Connection::open_in_memory().map_err(storage_error)?;
        initialize(&connection)?;
        let (frontier, recent_roots) = reconstruct_state(&connection)?;
        Ok(Self {
            state: Mutex::new(LedgerState {
                connection,
                frontier,
                recent_roots,
                issuer_key,
            }),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        Self::open_with_issuer(path, None)
    }

    pub fn open_with_issuer(
        path: impl AsRef<Path>,
        issuer_key: Option<IssuerVerifyingKey>,
    ) -> Result<Self, LedgerError> {
        let connection = Connection::open(path).map_err(storage_error)?;
        connection
            .busy_timeout(Duration::from_secs(10))
            .map_err(storage_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(storage_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(storage_error)?;
        initialize(&connection)?;
        let (frontier, recent_roots) = reconstruct_state(&connection)?;
        Ok(Self {
            state: Mutex::new(LedgerState {
                connection,
                frontier,
                recent_roots,
                issuer_key,
            }),
        })
    }

    /// Append a note commitment authorized by the configured issuance key.
    /// The issuer is the explicit supply trust anchor in this non-blockchain
    /// model; the ledger cannot prove off-ledger backing or prevent issuer
    /// inflation. The signature covers this protocol domain and exact cmx.
    pub fn issue_commitment(
        &self,
        commitment: [u8; 32],
        authorization: [u8; 64],
    ) -> Result<[u8; 32], LedgerError> {
        let cmx = parse_commitment(commitment)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerError::Storage("ledger mutex poisoned".to_owned()))?;
        let issuer_key = state
            .issuer_key
            .as_ref()
            .ok_or(LedgerError::IssuanceDisabled)?;
        let signature = Signature::from_bytes(&authorization);
        issuer_key
            .verify_strict(&issuance_message(&commitment), &signature)
            .map_err(|_| LedgerError::InvalidIssuanceAuthorization)?;

        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let (mut frontier, _) = reconstruct_state(&transaction)?;
        let leaf_index: i64 = transaction
            .query_row("SELECT COUNT(*) FROM commitments", [], |row| row.get(0))
            .map_err(storage_error)?;
        transaction.execute(
            "INSERT INTO commitments(leaf_index, commitment, accepted_bundle) VALUES (?1, ?2, ?3)",
            params![leaf_index, commitment.as_slice(), &[0u8; 32][..]],
        ).map_err(|error| if is_unique_violation(&error) { LedgerError::DuplicateCommitment } else { storage_error(error) })?;
        transaction
            .execute(
                "INSERT INTO issuances(commitment, authorization) VALUES (?1, ?2)",
                params![commitment.as_slice(), authorization.as_slice()],
            )
            .map_err(storage_error)?;
        if !frontier.append(MerkleHashOrchard::from_cmx(&cmx)) {
            return Err(LedgerError::CorruptState);
        }
        let root = frontier.root().to_bytes();
        transaction
            .execute(
                "INSERT INTO roots(leaf_count, root) VALUES (?1, ?2)",
                params![frontier.tree_size() as i64, root.as_slice()],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "DELETE FROM roots WHERE leaf_count NOT IN
             (SELECT leaf_count FROM roots ORDER BY leaf_count DESC LIMIT ?1)",
                [ANCHOR_WINDOW as i64],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        state.frontier = frontier;
        state.recent_roots.push_back(root);
        while state.recent_roots.len() > ANCHOR_WINDOW {
            state.recent_roots.pop_front();
        }
        Ok(root)
    }

    /// Verify a real Orchard proof and authorization, then atomically append
    /// nullifiers and output commitments. Only roots generated by this ledger's
    /// append-only commitment tree and retained in its 256-root window qualify.
    pub fn verify_and_apply(
        &self,
        bundle: &Bundle<Authorized, i64>,
        verifying_key: &VerifyingKey,
        tx_version: TxVersion,
    ) -> Result<(), LedgerError> {
        let spend = verify_spend(bundle, verifying_key, tx_version)?;
        self.apply(&spend)
    }

    /// Apply previously verified public transition data atomically.
    pub fn apply(&self, spend: &VerifiedSpend) -> Result<(), LedgerError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerError::Storage("ledger mutex poisoned".to_owned()))?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        // Reload under the write lock so separate ledger processes cannot
        // append from stale frontiers or accept an anchor pruned by another.
        let (mut next_frontier, current_roots) = reconstruct_state(&transaction)?;
        if !current_roots.contains(&spend.anchor) {
            return Err(LedgerError::UnknownAnchor);
        }
        for nullifier in &spend.nullifiers {
            transaction
                .execute(
                    "INSERT INTO nullifiers(nullifier, accepted_bundle) VALUES (?1, ?2)",
                    params![nullifier.as_slice(), spend.bundle_id.as_slice()],
                )
                .map_err(|error| {
                    if is_unique_violation(&error) {
                        LedgerError::DuplicateNullifier
                    } else {
                        storage_error(error)
                    }
                })?;
        }
        for output in &spend.outputs {
            let leaf_index: i64 = transaction
                .query_row("SELECT COUNT(*) FROM commitments", [], |row| row.get(0))
                .map_err(storage_error)?;
            transaction.execute(
                "INSERT INTO commitments(leaf_index, commitment, accepted_bundle) VALUES (?1, ?2, ?3)",
                params![leaf_index, output.as_slice(), spend.bundle_id.as_slice()],
            ).map_err(|error| if is_unique_violation(&error) { LedgerError::DuplicateCommitment } else { storage_error(error) })?;
            let cmx = parse_commitment(*output)?;
            if !next_frontier.append(MerkleHashOrchard::from_cmx(&cmx)) {
                return Err(LedgerError::CorruptState);
            }
        }
        let new_root = next_frontier.root().to_bytes();
        let leaf_count = next_frontier.tree_size() as i64;
        transaction
            .execute(
                "INSERT INTO roots(leaf_count, root) VALUES (?1, ?2)",
                params![leaf_count, new_root.as_slice()],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "INSERT INTO accepted_bundles(bundle_id) VALUES (?1)",
                [spend.bundle_id.as_slice()],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "DELETE FROM roots WHERE leaf_count NOT IN
                 (SELECT leaf_count FROM roots ORDER BY leaf_count DESC LIMIT ?1)",
                [ANCHOR_WINDOW as i64],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;

        state.frontier = next_frontier;
        state.recent_roots = current_roots;
        state.recent_roots.push_back(new_root);
        while state.recent_roots.len() > ANCHOR_WINDOW {
            state.recent_roots.pop_front();
        }
        Ok(())
    }
}

/// Domain-separated bytes signed by the configured issuer for a commitment.
pub fn issuance_message(commitment: &[u8; 32]) -> Vec<u8> {
    [b"0PSP-R/ISSUE/v1\0".as_slice(), commitment].concat()
}

/// Pure cryptographic verification. It has no ledger or persistence side
/// effects; the caller must still apply the returned transition to an
/// authoritative state machine that enforces root policy and nullifier
/// uniqueness.
pub fn verify_spend(
    bundle: &Bundle<Authorized, i64>,
    verifying_key: &VerifyingKey,
    tx_version: TxVersion,
) -> Result<VerifiedSpend, LedgerError> {
    verify_bundle(bundle, verifying_key, tx_version)?;
    let bundle_id: [u8; 32] = bundle
        .commitment(tx_version)
        .map_err(|_| LedgerError::InvalidAuthorization)?
        .into();
    Ok(VerifiedSpend {
        bundle_id,
        anchor: bundle.anchor().to_bytes(),
        nullifiers: bundle
            .actions()
            .into_iter()
            .map(|action| action.nullifier().to_bytes())
            .collect(),
        outputs: bundle
            .actions()
            .into_iter()
            .map(|action| action.cmx().to_bytes())
            .collect(),
    })
}

fn initialize(connection: &Connection) -> Result<(), LedgerError> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS commitments (
            leaf_index INTEGER NOT NULL UNIQUE,
            commitment BLOB PRIMARY KEY CHECK(length(commitment) = 32),
            accepted_bundle BLOB NOT NULL CHECK(length(accepted_bundle) = 32)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS roots (
            leaf_count INTEGER PRIMARY KEY,
            root BLOB NOT NULL CHECK(length(root) = 32)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS issuances (
            commitment BLOB PRIMARY KEY CHECK(length(commitment) = 32),
            authorization BLOB NOT NULL CHECK(length(authorization) = 64)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS nullifiers (
            nullifier BLOB PRIMARY KEY CHECK(length(nullifier) = 32),
            accepted_bundle BLOB NOT NULL CHECK(length(accepted_bundle) = 32)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS accepted_bundles (
            bundle_id BLOB PRIMARY KEY CHECK(length(bundle_id) = 32)
         ) WITHOUT ROWID;",
        )
        .map_err(storage_error)
}

fn reconstruct_state(
    connection: &Connection,
) -> Result<(CommitmentTree, VecDeque<[u8; 32]>), LedgerError> {
    let mut frontier = CommitmentTree::empty();
    let mut stmt = connection
        .prepare("SELECT leaf_index, commitment FROM commitments ORDER BY leaf_index")
        .map_err(storage_error)?;
    let mut rows = stmt.query([]).map_err(storage_error)?;
    let mut expected_index = 0i64;
    let mut recomputed = Vec::new();
    while let Some(row) = rows.next().map_err(storage_error)? {
        let index: i64 = row.get(0).map_err(storage_error)?;
        let commitment: Vec<u8> = row.get(1).map_err(storage_error)?;
        if index != expected_index {
            return Err(LedgerError::CorruptState);
        }
        let cmx = parse_commitment(
            commitment
                .as_slice()
                .try_into()
                .map_err(|_| LedgerError::CorruptState)?,
        )?;
        if !frontier.append(MerkleHashOrchard::from_cmx(&cmx)) {
            return Err(LedgerError::CorruptState);
        }
        expected_index += 1;
        recomputed.push((expected_index, frontier.root().to_bytes()));
    }
    let mut stored = connection
        .prepare("SELECT leaf_count, root FROM roots ORDER BY leaf_count")
        .map_err(storage_error)?;
    let roots = stored
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(storage_error)?;
    let mut recent = VecDeque::new();
    for row in roots {
        let (count, root) = row.map_err(storage_error)?;
        let root: [u8; 32] = root.try_into().map_err(|_| LedgerError::CorruptState)?;
        let matches_recomputed = if count == 0 {
            CommitmentTree::empty().root().to_bytes() == root
        } else {
            recomputed.get(count as usize - 1).map(|entry| entry.1) == Some(root)
        };
        if !matches_recomputed {
            return Err(LedgerError::CorruptState);
        }
        recent.push_back(root);
    }
    if recent.is_empty() {
        let root = frontier.root().to_bytes();
        connection
            .execute(
                "INSERT INTO roots(leaf_count, root) VALUES (0, ?1)",
                [root.as_slice()],
            )
            .map_err(storage_error)?;
        recent.push_back(root);
    }
    while recent.len() > ANCHOR_WINDOW {
        recent.pop_front();
    }
    Ok((frontier, recent))
}

fn parse_commitment(bytes: [u8; 32]) -> Result<ExtractedNoteCommitment, LedgerError> {
    Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
        .ok_or(LedgerError::InvalidCommitment)
}

fn verify_bundle(
    bundle: &Bundle<Authorized, i64>,
    verifying_key: &VerifyingKey,
    tx_version: TxVersion,
) -> Result<(), LedgerError> {
    if *bundle.value_balance() != 0 {
        return Err(LedgerError::PublicValueBalance);
    }
    bundle
        .verify_proof(verifying_key)
        .map_err(|_| LedgerError::InvalidProof)?;
    let sighash: [u8; 32] = bundle
        .commitment(tx_version)
        .map_err(|_| LedgerError::InvalidAuthorization)?
        .into();
    for action in bundle.actions() {
        action
            .rk()
            .verify(&sighash, action.authorization())
            .map_err(|_| LedgerError::InvalidAuthorization)?;
    }
    bundle
        .binding_validating_key()
        .verify(&sighash, bundle.authorization().binding_signature())
        .map_err(|_| LedgerError::InvalidAuthorization)
}

fn storage_error(error: rusqlite::Error) -> LedgerError {
    LedgerError::Storage(error.to_string())
}
fn is_unique_violation(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::SqliteFailure(code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation)
}
