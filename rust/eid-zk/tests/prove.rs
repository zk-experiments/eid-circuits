//! Proves and verifies every chain of noir/circuits/chains.json (inputs from
//! each package's Chain.toml) with the frozen registry, bytecode from a
//! release-asset directory checked against its pinned hash.
//!
//! Runs when `EID_ZK_ASSETS` is set (`mise run test:prove`: the directory
//! `noir-zk freeze` wrote, or a downloaded release). `EID_ZK_CLI_PROOF`
//! optionally names a `fold.py --out` directory whose `bb` CLI proof must
//! verify here too.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use eid_zk::{artifacts, hiding_vk, prove_document, verify_document, vk_tree_root};
use eid_zk::{DirStore, Document, FoldedProof, Inputs};
use noir_zk_backend::chonk;
use noir_zk_core::Artifacts;

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
    let Some(assets) = std::env::var_os("EID_ZK_ASSETS").map(PathBuf::from) else {
        return;
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let frozen = artifacts(DirStore(assets.clone())).unwrap();
    let chains: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("noir/circuits/chains.json")).unwrap(),
    )
    .unwrap();
    let mut last = None;
    for chain in chains["chains"].as_array().unwrap() {
        let name = |k: &str| chain[k].as_str().unwrap();
        let (d, s, e) = (
            chain_toml(&root, name("dsc")),
            chain_toml(&root, name("sod")),
            chain_toml(&root, name("envelope")),
        );
        let doc = Document {
            dsc: (name("dsc"), Inputs::Toml(&d)),
            sod: (name("sod"), Inputs::Toml(&s)),
            envelope: (name("envelope"), Inputs::Toml(&e)),
        };
        let (proof, public) = prove_document(&frozen, &doc).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 39_872);
        let verified = verify_document(
            &FoldedProof::from_bytes(&bytes).unwrap(),
            hiding_vk(),
            vk_tree_root(),
        )
        .unwrap();
        assert_eq!(verified, public);
        last = Some(bytes);
    }

    // A flipped public byte breaks verification.
    let mut tampered = last.unwrap();
    tampered[31] ^= 1;
    assert!(!chonk::verify(&FoldedProof::from_bytes(&tampered).unwrap(), hiding_vk()).unwrap());

    // A tampered asset is refused before it reaches the solver.
    let tmp = std::env::temp_dir().join(format!("eid-zk-tamper-{}", std::process::id()));
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
    if let Some(dir) = std::env::var_os("EID_ZK_CLI_PROOF").map(PathBuf::from) {
        let cli = FoldedProof::from_bytes(&std::fs::read(dir.join("proof")).unwrap()).unwrap();
        assert!(chonk::verify(&cli, &std::fs::read(dir.join("vk")).unwrap()).unwrap());
    }
}
