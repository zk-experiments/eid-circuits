//! `noir/circuits/vk-tree.json`: the tree of verification keys the kernels
//! accept. Every step circuit and every kernel but the hiding kernel is a
//! leaf `H(role, H(vk))`, so a proof can use any step variant without the
//! verifier learning which, and a key can't stand in for another role.
//!
//! Keys come from `bb write_vk --scheme chonk` on the compiled artifacts in
//! `target/` (run `nargo compile --workspace` first). Entries whose bytecode
//! hash is unchanged are reused, so a refresh only calls bb for what changed.
//! The leaves are sorted by value, as csca-registry's ordered tree requires.

use crate::root;
use anyhow::{bail, Context, Result};
use ark_ff::PrimeField;
use csca_registry::commitment::{from_hex, poseidon2, to_hex, Tree};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// `eid_kernel::VK_TREE_HEIGHT`.
const HEIGHT: usize = 9;
pub(crate) const PATH: &str = "noir/circuits/vk-tree.json";

/// `eid_kernel::ROLE_*` of a package, or `None` if it is not in the tree.
pub(crate) fn role(package: &str) -> Option<u64> {
    Some(match package {
        p if p.starts_with("dsc_") => 1,
        p if p.starts_with("sod_") => 2,
        p if p.starts_with("envelope_") => 3,
        "kernel_dsc" => 4,
        "kernel_sod" => 5,
        "kernel_envelope" => 6,
        "kernel_tail" => 7,
        _ => return None,
    })
}

/// SHA-256 of an artifact's bytecode (as `circuit_sizes.py` records it).
fn bytecode_sha256(artifact: &Path) -> Result<String> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(artifact)?)?;
    let bytecode = v["bytecode"].as_str().context("artifact has no bytecode")?;
    Ok(hex::encode(Sha256::digest(bytecode.as_bytes())))
}

/// Poseidon2 hash of a Chonk verification key, as `eid_kernel::check_vk` computes it.
fn vk_hash(bb: &str, artifact: &Path) -> Result<String> {
    let dir = std::env::temp_dir().join(format!("eid-vk-{}", std::process::id()));
    let out = std::process::Command::new(bb)
        .args([
            "write_vk",
            "--scheme",
            "chonk",
            "--circuit_kind",
            if artifact.to_string_lossy().contains("kernel_") {
                "kernel"
            } else {
                "app"
            },
            "--output_format",
            "json",
            "-b",
        ])
        .arg(artifact)
        .arg("-o")
        .arg(&dir)
        .output()
        .with_context(|| format!("running {bb}"))?;
    if !out.status.success() {
        bail!(
            "bb write_vk failed for {}: {}",
            artifact.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("vk.json"))?)?;
    let fields = v["vk"]
        .as_array()
        .context("vk.json has no vk")?
        .iter()
        .map(|f| {
            let s = f.as_str().context("vk field")?;
            Ok(ark_bn254::Fr::from_be_bytes_mod_order(&hex::decode(
                s.trim_start_matches("0x"),
            )?))
        })
        .collect::<Result<Vec<_>>>()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(to_hex(&poseidon2(&fields)))
}

/// The tree file for the packages in `packages` (compiled into `target/`),
/// reusing `previous` entries whose bytecode is unchanged.
pub(crate) fn build(packages: &[String], previous: Option<&Value>, bb: &str) -> Result<String> {
    let cached: BTreeMap<String, (String, String)> = previous
        .and_then(|p| p["leaves"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|l| {
            Some((
                l["package"].as_str()?.to_string(),
                (
                    l["bytecode_sha256"].as_str()?.to_string(),
                    l["vk_hash"].as_str()?.to_string(),
                ),
            ))
        })
        .collect();
    let mut entries = vec![];
    for p in packages {
        let Some(role) = role(p) else { continue };
        let artifact = root().join(format!("target/{p}.json"));
        let sha = bytecode_sha256(&artifact)
            .with_context(|| format!("{p}: compile the workspace first"))?;
        let vk = match cached.get(p) {
            Some((s, h)) if *s == sha => h.clone(),
            _ => vk_hash(bb, &artifact)?,
        };
        let leaf = poseidon2(&[ark_bn254::Fr::from(role), from_hex(&vk)?]);
        entries.push((p.clone(), role, sha, vk, leaf));
    }
    let mut leaves: Vec<_> = entries.iter().map(|e| e.4).collect();
    leaves.sort();
    let tree = Tree::new(leaves.clone(), HEIGHT)?;
    let out: Vec<Value> = entries
        .iter()
        .map(|(p, role, sha, vk, leaf)| {
            let index = leaves.binary_search(leaf).unwrap_or(usize::MAX);
            let proof = tree.proof(index);
            json!({
                "package": p,
                "role": role,
                "bytecode_sha256": sha,
                "vk_hash": vk,
                "index": index,
                "siblings": proof.siblings.iter().map(to_hex).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut s = serde_json::to_string_pretty(&json!({
        "generated_by": "eid-vectors vk-tree (rust/eid-vectors/src/vktree.rs); do not edit",
        "height": HEIGHT,
        "root": to_hex(&tree.root()),
        "leaves": out,
    }))?;
    s.push('\n');
    Ok(s)
}
