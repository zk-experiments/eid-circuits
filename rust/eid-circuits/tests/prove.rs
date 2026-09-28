//! Proves and verifies every chain of noir/circuits/chains.json (inputs from
//! each package's Chain.toml) with the frozen registry, bytecode from a
//! release-asset directory checked against its pinned hash.
//!
//! Runs when `EID_ASSETS` is set (`mise run test:prove`: the directory
//! `noir-zk freeze` wrote, or a downloaded release). `EID_CLI_PROOF`
//! optionally names a `fold.py --out` directory whose `bb` CLI proof must
//! verify here too.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use eid_circuits::circuits::kernel_dsc::KernelDsc;
use eid_circuits::circuits::kernel_envelope::KernelEnvelope;
use eid_circuits::circuits::kernel_hiding::KernelHiding;
use eid_circuits::circuits::kernel_sod::KernelSod;
use eid_circuits::circuits::kernel_tail::KernelTail;
use eid_circuits::{artifacts, vk_tree_root, DirStore};

use noir_zk_backend::chonk::{self, FoldedProof};
use noir_zk_backend::fold::{verify, Folding};
use noir_zk_core::{Artifacts, CircuitId, Error, Field};

/// A document proof's size, the same for every document.
const PROOF_BYTES: usize = 39_616;

/// `toml` with the line `key = ...` replaced by `key = "value"`.
fn set(toml: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key} = ");
    toml.lines()
        .map(|l| {
            if l.starts_with(&prefix) {
                format!("{prefix}\"{value}\"")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The nullifier `eid_envelope` computes for an envelope step's inputs.
fn expected_nullifier(envelope: &str) -> (Field, Field) {
    let t: toml::Table = toml::from_str(envelope).unwrap();
    let field = |v: &toml::Value| v.as_str().unwrap().parse::<Field>().unwrap();
    let scope = field(&t["scope"]);
    let w = t["w"].as_table().unwrap();
    let len = usize::try_from(w["digest_len"].as_integer().unwrap()).unwrap();
    let digest: Vec<u8> = w["digest"].as_array().unwrap()[..len]
        .iter()
        .map(|b| u8::try_from(b.as_integer().unwrap()).unwrap())
        .collect();
    (scope, eid_envelope::nullifier(scope, &digest).unwrap())
}

fn prove(
    frozen: &impl Artifacts,
    chain: &serde_json::Value,
    d: &str,
    s: &str,
    e: &str,
) -> Result<
    (
        FoldedProof,
        eid_circuits::circuits::kernel_hiding::PublicOutputs,
    ),
    Error,
> {
    let name = |k: &str| chain[k].as_str().unwrap();
    // Circuits picked at runtime (by label) are wrapped with the kernel
    // that folds them; the chain type-checks at compile time.
    Folding::new(frozen)
        .app(KernelDsc::select(name("dsc"), d)?)?
        .app(KernelSod::select(name("sod"), s)?)?
        .app(KernelEnvelope::select(name("envelope"), e)?)?
        .kernel::<KernelTail>()?
        .hiding::<KernelHiding>()
}

fn chain_toml(root: &Path, name: &str) -> String {
    let ws = std::fs::read_to_string(root.join("Nargo.toml")).unwrap();
    let dir = ws
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"')?.strip_suffix("\","))
        .map(|m| root.join(m))
        .find(|d| {
            std::fs::read_to_string(d.join("Nargo.toml"))
                .is_ok_and(|t| t.contains(&format!("name = \"{name}\"")))
        })
        .unwrap();
    std::fs::read_to_string(dir.join("Chain.toml")).unwrap()
}

#[test]
fn proves_and_verifies_every_chain() {
    let Some(assets) = std::env::var_os("EID_ASSETS").map(PathBuf::from) else {
        return;
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Downloaded files match the pins compiled into the crate.
    let checked =
        noir_zk_backend::frozen::verify_dir(eid_circuits::circuits::REGISTRY, &assets).unwrap();
    assert!(checked > 0);
    let frozen = artifacts(DirStore(assets.clone())).unwrap();
    let chains: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("noir/circuits/chains.json")).unwrap(),
    )
    .unwrap();
    let mut last = None;
    let chains = chains["chains"].as_array().unwrap();
    for chain in chains {
        let name = |k: &str| chain[k].as_str().unwrap();
        let (d, s, e) = (
            chain_toml(&root, name("dsc")),
            chain_toml(&root, name("sod")),
            chain_toml(&root, name("envelope")),
        );
        let (proof, public) = prove(&frozen, chain, &d, &s, &e).unwrap();
        let (scope, nullifier) = expected_nullifier(&e);
        assert_eq!((public.scope, public.nullifier), (scope, nullifier));
        assert_ne!(nullifier, Field::from(0u64));
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), PROOF_BYTES);
        let verified =
            verify::<KernelHiding>(&FoldedProof::from_bytes(&bytes).unwrap(), vk_tree_root())
                .unwrap();
        assert_eq!(verified, public);
        assert_eq!(public.vk_tree_root, vk_tree_root());
        last = Some(bytes);
    }

    // The nullifier is the document's in the scope: the same with fresh
    // envelope randomness, another in another scope, 0 without a scope.
    let chain = &chains[0];
    let name = |k: &str| chain[k].as_str().unwrap();
    let (d, s, e) = (
        chain_toml(&root, name("dsc")),
        chain_toml(&root, name("sod")),
        chain_toml(&root, name("envelope")),
    );
    let (scope, nullifier) = expected_nullifier(&e);
    let fresh = set(&set(&e, "ephemeral", "1234567"), "key", "7654321");
    let other = set(&e, "scope", &(scope + Field::from(1u64)).to_string());
    let none = set(&e, "scope", "0");
    let nf = |e: &str| prove(&frozen, chain, &d, &s, e).unwrap().1.nullifier;
    assert_eq!(nf(&fresh), nullifier);
    let n = nf(&other);
    assert_ne!(n, nullifier);
    assert_eq!(n, expected_nullifier(&other).1);
    assert_eq!(nf(&none), Field::from(0u64));

    // A flipped public byte breaks verification.
    let mut tampered = last.unwrap();
    tampered[31] ^= 1;
    assert!(!chonk::verify(
        &FoldedProof::from_bytes(&tampered).unwrap(),
        KernelHiding::VK_BYTES
    )
    .unwrap());

    // A tampered asset is refused before it reaches the solver.
    let tmp = std::env::temp_dir().join(format!("eid-circuits-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let asset = std::fs::read_dir(&assets).unwrap().next().unwrap().unwrap();
    let mut bytes = std::fs::read(asset.path()).unwrap();
    bytes[10] ^= 1;
    std::fs::write(tmp.join(asset.file_name()), bytes).unwrap();
    let label = asset
        .file_name()
        .to_string_lossy()
        .split('@')
        .next()
        .unwrap()
        .to_string();
    let err = artifacts(DirStore(tmp.clone()))
        .unwrap()
        .bytecode_b64(&label)
        .unwrap_err();
    assert!(err.to_string().contains("pinned hash"), "{err}");
    let _ = std::fs::remove_dir_all(tmp);

    // A proof written by `bb prove --scheme chonk` verifies here too.
    if let Some(dir) = std::env::var_os("EID_CLI_PROOF").map(PathBuf::from) {
        let cli = FoldedProof::from_bytes(&std::fs::read(dir.join("proof")).unwrap()).unwrap();
        assert!(chonk::verify(&cli, &std::fs::read(dir.join("vk")).unwrap()).unwrap());
    }
}
