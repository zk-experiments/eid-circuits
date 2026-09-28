//! Shared by the kernel circuits that fold the three steps with Chonk
//! (barretenberg's client-side IVC) into one proof:
//!
//! ```text
//! DSC step -> kernel_dsc -> SOD step -> kernel_sod -> envelope step -> kernel_envelope
//!          -> kernel_tail -> kernel_hiding (public outputs)
//! ```
//!
//! Each kernel folds the previous kernel and its step, checks both
//! verification keys are in the published key tree under their role (so any
//! of the ~300 step variants can be used without revealing which), checks
//! the step continues the previous one (commitments), and passes the state
//! on through the databus. Specification: docs/FOLDING.md.

use csca_registry::{hash, merkle_root, MerklePath};

mod tests;

/// Fields of a Chonk (Mega) verification key (bb 7.0.0-nightly.20260927).
pub global VK_FIELDS: u32 = 151;
/// Height of the verification key tree (512 leaves).
pub global VK_TREE_HEIGHT: u32 = 9;

/// Recursion proof types of bb 7.0.0-nightly.20260927: OINK folds the first
/// circuit, HN every later one (the tail included), HN_FINAL the hiding step.
pub global PROOF_TYPE_OINK: u32 = 1;
pub global PROOF_TYPE_HN: u32 = 2;
pub global PROOF_TYPE_HN_FINAL: u32 = 7;

/// Roles a key tree leaf commits to: `leaf = H(role, H(vk))`.
pub global ROLE_DSC: Field = 1;
pub global ROLE_SOD: Field = 2;
pub global ROLE_ENVELOPE: Field = 3;
pub global ROLE_KERNEL_DSC: Field = 4;
pub global ROLE_KERNEL_SOD: Field = 5;
pub global ROLE_KERNEL_ENVELOPE: Field = 6;
pub global ROLE_KERNEL_TAIL: Field = 7;

/// A verification key and its place in the key tree.
pub struct Vk {
    pub key: [Field; VK_FIELDS],
    pub path: MerklePath<VK_TREE_HEIGHT>,
}

/// Asserts `vk` is in the key tree with root `root` under `role` and returns
/// its hash (bb checks the folded proof against it).
pub fn check_vk(root: Field, role: Field, vk: Vk) -> Field {
    let vk_hash = hash(vk.key);
    assert_eq(
        merkle_root(hash([role, vk_hash]), vk.path),
        root,
        "verification key is not in the key tree under its role",
    );
    vk_hash
}

/// State passed between kernels:
/// `[registry_root, vk_tree_root, link, uses_sha1, date, context,
///   viewer (x, y), E.x, E.y, wrapped, ciphertext × 6, scope, nullifier]`.
/// `link` is the commitment the next step must continue from.
pub global STATE_FIELDS: u32 = 19;
pub global S_REGISTRY_ROOT: u32 = 0;
pub global S_VK_TREE_ROOT: u32 = 1;
pub global S_LINK: u32 = 2;
pub global S_USES_SHA1: u32 = 3;
pub global S_ENVELOPE: u32 = 4;
pub global S_SCOPE: u32 = 17;
pub global S_NULLIFIER: u32 = 18;

/// Hash id of SHA-1 (`eid_steps::HASH_SHA1`).
pub global HASH_SHA1: Field = 1;

/// 1 when `hash_id` is SHA-1, else 0.
pub fn is_sha1(hash_id: Field) -> Field {
    (hash_id == HASH_SHA1) as Field
}

/// `a` or `b` for 0/1 flags.
pub fn or(a: Field, b: Field) -> Field {
    a + b - a * b
}

/// What the folded proof makes public (the hiding kernel's outputs).
pub struct PublicOutputs {
    /// csca-registry root the DSC step was proven against.
    pub registry_root: Field,
    /// Root of the verification key tree every step and kernel was checked against.
    pub vk_tree_root: Field,
    /// 1 when any step hashed with SHA-1.
    pub uses_sha1: Field,
    /// Proof date, context and the viewer key the envelope step used.
    pub date: Field,
    pub context: Field,
    pub viewer: [Field; 2],
    /// The envelope: `E`, the wrapped key, the ciphertext.
    pub ephemeral: [Field; 2],
    pub wrapped: Field,
    pub ciphertext: [Field; 6],
    /// The scope the nullifier is for, and the document's nullifier in it
    /// (both 0 when the proof has no scope).
    pub scope: Field,
    pub nullifier: Field,
}

/// The public outputs from the final state.
pub fn public_outputs(s: [Field; STATE_FIELDS]) -> PublicOutputs {
    let mut ciphertext: [Field; 6] = [0; 6];
    for i in 0..6 {
        ciphertext[i] = s[11 + i];
    }
    PublicOutputs {
        registry_root: s[S_REGISTRY_ROOT],
        vk_tree_root: s[S_VK_TREE_ROOT],
        uses_sha1: s[S_USES_SHA1],
        date: s[4],
        context: s[5],
        viewer: [s[6], s[7]],
        ephemeral: [s[8], s[9]],
        wrapped: s[10],
        ciphertext,
        scope: s[S_SCOPE],
        nullifier: s[S_NULLIFIER],
    }
}
