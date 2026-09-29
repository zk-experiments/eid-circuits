//! Folds every chain of noir/circuits/chains.json (inputs from each package's
//! Chain.toml) through noir-zk's generic kernels in the test-only pipeline
//! `[dsc, sod, document]`, in-process (`PipelineFold`), and verifies the
//! proof: the identity layer's families chain and prove as a combining
//! registry will fold them. Nothing is timed or measured in CI.
//!
//! Runs when `EID_TARGET` (nargo's `target/`, the compiled samples) or
//! `EID_ASSETS` (a release-asset directory, checked against the pins) is set.
//! `mise run fold:record` sets `EID_RECORD=<fold-times.json>`,
//! `EID_THREADS=4,18` and `EID_MACHINE`: every chain is then proven in a
//! child process per thread count and the runs written to the file.

#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use ark_ff::{PrimeField, Zero};
use eid_circuits::circuits::families::{KernelStepDocument, KernelStepDsc, KernelStepSod};
use eid_circuits::circuits::FAMILIES;
use eid_circuits::{artifacts, DirStore};
use noir_zk_backend::chonk::FoldedProof;
use noir_zk_backend::pipeline::{self, PipelineFold};
use noir_zk_core::codec::field_to_be_bytes32;
use noir_zk_core::tree::{Tree, DEPLOYMENT_HEIGHT, PIPELINE_HEIGHT};
use noir_zk_core::{
    Artifacts, DeploymentEntry, Error, Field, Merged, PipelineEntry, PositionEntry, StepFamily,
};

/// The test-only pipeline: the three families in order, each position's
/// layout resolved against the slots published before it.
static PIPELINE: LazyLock<PipelineEntry> = LazyLock::new(|| {
    let mut published: Vec<&'static str> = vec![];
    let mut positions = vec![];
    for name in ["dsc", "sod", "document"] {
        let f = eid_circuits::family(name).unwrap();
        positions.push(PositionEntry {
            family: f.id,
            layout: f.layout(&published).unwrap(),
        });
        published.extend(f.slots);
    }
    let roots = |id: &noir_zk_core::FamilyRef| {
        FAMILIES
            .iter()
            .find(|f| f.id == *id)
            .map(|f| f.root_field())
    };
    let leaves = PipelineEntry::leaves(
        &roots,
        &positions,
        noir_zk_backend::kernels::FAMILY.root_field(),
    )
    .unwrap();
    PipelineEntry {
        name: "eid_document",
        index: 0,
        positions,
        slots: published,
        root: field_to_be_bytes32(&Tree::build(&leaves, PIPELINE_HEIGHT).root),
    }
});

/// A deployment of that one pipeline.
static DEPLOYMENT: LazyLock<DeploymentEntry> = LazyLock::new(|| {
    let root = PIPELINE.root_field();
    DeploymentEntry {
        roots: Box::leak(vec![PIPELINE.root].into_boxed_slice()),
        root: field_to_be_bytes32(&Tree::build(&[root], DEPLOYMENT_HEIGHT).root),
    }
});

/// nargo's `target/` as an artifact store: the asset `<label>@<version>.b64`
/// is `<label>.json`'s bytecode (checked against its pin by `Frozen`).
struct NargoTarget(PathBuf);

impl noir_zk_backend::ArtifactStore for NargoTarget {
    fn fetch(&self, asset: &str) -> Result<Vec<u8>, Error> {
        let label = asset.split('@').next().unwrap_or(asset);
        let path = self.0.join(format!("{label}.json"));
        let json = std::fs::read_to_string(&path).map_err(|e| {
            Error::Artifact(format!(
                "{}: {e} (nargo compile --package {label})",
                path.display()
            ))
        })?;
        let v: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| Error::Artifact(format!("{label}: {e}")))?;
        v["bytecode"]
            .as_str()
            .map(|b| b.as_bytes().to_vec())
            .ok_or_else(|| Error::Artifact(format!("{label}: no bytecode")))
    }
}

/// The frozen circuits over whichever store the environment names.
fn store() -> Option<Box<dyn Artifacts>> {
    if let Some(dir) = std::env::var_os("EID_ASSETS").map(PathBuf::from) {
        // Downloaded files match the pins compiled into the crate.
        let checked =
            noir_zk_backend::frozen::verify_dir(eid_circuits::circuits::REGISTRY, &dir).unwrap();
        assert!(checked > 0);
        return Some(Box::new(artifacts(DirStore(dir))));
    }
    std::env::var_os("EID_TARGET")
        .map(|t| Box::new(artifacts(NargoTarget(PathBuf::from(t)))) as Box<dyn Artifacts>)
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn chains() -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("noir/circuits/chains.json")).unwrap(),
    )
    .unwrap();
    v["chains"].as_array().unwrap().clone()
}

fn chain_toml(name: &str) -> String {
    let root = root();
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

/// The nullifier `eid_steps::document::nullifier` computes for a document
/// step's inputs: `H(NULLIFIER, scope, digest_len, pack_be(digest))`.
fn expected_nullifier(document: &str) -> (Field, Field) {
    let t: toml::Table = toml::from_str(document).unwrap();
    let field = |v: &toml::Value| v.as_str().unwrap().parse::<Field>().unwrap();
    let scope = field(&t["scope"]);
    let w = t["w"].as_table().unwrap();
    let len = usize::try_from(w["digest_len"].as_integer().unwrap()).unwrap();
    let mut digest: Vec<u8> = w["digest"].as_array().unwrap()[..len]
        .iter()
        .map(|b| u8::try_from(b.as_integer().unwrap()).unwrap())
        .collect();
    if scope.is_zero() {
        return (scope, Field::from(0u64));
    }
    digest.resize(64, 0);
    let mut inputs = vec![
        Field::from_be_bytes_mod_order(b"eid-nullifier/v1"),
        scope,
        Field::from(u64::try_from(len).unwrap()),
    ];
    inputs.extend(digest.rchunks(31).map(Field::from_be_bytes_mod_order));
    (scope, csca_registry::commitment::poseidon2(&inputs))
}

/// The public slots of a verified proof: registry root, date, scope, nullifier.
struct Outputs {
    registry_root: Field,
    date: Field,
    scope: Field,
    nullifier: Field,
}

fn fold(
    pool: &dyn Artifacts,
    chain: &serde_json::Value,
    d: &str,
    s: &str,
    e: &str,
) -> Result<(FoldedProof, Outputs), Error> {
    let name = |k: &str| chain[k].as_str().unwrap();
    let (proof, fields) = PipelineFold::new(pool, &PIPELINE)?
        .app(KernelStepDsc::select(name("dsc"), d.to_string())?)?
        .app(KernelStepSod::select(name("sod"), s.to_string())?)?
        .app(KernelStepDocument::select(name("document"), e.to_string())?)?
        .hiding(&DEPLOYMENT)?;
    let verified = pipeline::verify(
        &proof,
        &PIPELINE,
        DEPLOYMENT.root_field(),
        pipeline::hiding_vk(),
    )?;
    assert_eq!(verified, fields);
    assert_eq!(
        PIPELINE.slots,
        ["registry_root", "date", "scope", "nullifier"]
    );
    Ok((
        proof,
        Outputs {
            registry_root: fields[3],
            date: fields[4],
            scope: fields[5],
            nullifier: fields[6],
        },
    ))
}

#[test]
fn folds_and_verifies_every_chain() {
    let Some(frozen) = store() else {
        return;
    };
    if let Ok(one) = std::env::var("EID_ONE") {
        // A child of the recorder: one chain, timed, printed as JSON.
        return one_run(&*frozen, &one);
    }
    let pool = Merged::new(&[&*frozen, &noir_zk_backend::kernels::Kernels]);
    let chains = chains();
    let mut last = None;
    for chain in &chains {
        let name = |k: &str| chain[k].as_str().unwrap();
        let (d, s, e) = (
            chain_toml(name("dsc")),
            chain_toml(name("sod")),
            chain_toml(name("document")),
        );
        let (proof, o) = fold(&pool, chain, &d, &s, &e).unwrap();
        let (scope, nullifier) = expected_nullifier(&e);
        assert_eq!(
            (o.scope, o.nullifier),
            (scope, nullifier),
            "{}",
            name("name")
        );
        assert_ne!(nullifier, Field::from(0u64));
        let t: toml::Table = toml::from_str(&d).unwrap();
        let root = hex::decode(t["root"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(o.registry_root, Field::from_be_bytes_mod_order(&root));
        let t: toml::Table = toml::from_str(&e).unwrap();
        assert_eq!(
            o.date,
            Field::from(t["date"].as_integer().unwrap().unsigned_abs())
        );
        eprintln!(
            "{}: proven and verified ({} bytes)",
            name("name"),
            proof.to_bytes().len()
        );
        last = Some(proof);
    }

    // The nullifier is the document's in the scope: the same under another
    // payload salt, another in another scope, 0 without a scope.
    let chain = &chains[0];
    let name = |k: &str| chain[k].as_str().unwrap();
    let (d, s, e) = (
        chain_toml(name("dsc")),
        chain_toml(name("sod")),
        chain_toml(name("document")),
    );
    let (scope, nullifier) = expected_nullifier(&e);
    let fresh = set(&e, "dg1_salt", "1234567");
    let other = set(&e, "scope", &(scope + Field::from(1u64)).to_string());
    let none = set(&e, "scope", "0");
    let nf = |e: &str| fold(&pool, chain, &d, &s, e).unwrap().1.nullifier;
    assert_eq!(nf(&fresh), nullifier);
    let n = nf(&other);
    assert_ne!(n, nullifier);
    assert_eq!(n, expected_nullifier(&other).1);
    assert_eq!(nf(&none), Field::from(0u64));

    // A broken link (another document's SOD after this DSC) is refused by
    // the kernel: no proof exists.
    let other_chain = &chains[1];
    let bad_sod = chain_toml(other_chain["sod"].as_str().unwrap());
    let mixed = serde_json::json!({
        "dsc": name("dsc"),
        "sod": other_chain["sod"],
        "document": name("document"),
    });
    assert!(
        fold(&pool, &mixed, &d, &bad_sod, &e).is_err(),
        "the link c_A must chain"
    );

    // A flipped public byte breaks verification.
    let mut tampered = last.unwrap().to_bytes();
    tampered[31] ^= 1;
    assert!(pipeline::verify(
        &FoldedProof::from_bytes(&tampered).unwrap(),
        &PIPELINE,
        DEPLOYMENT.root_field(),
        pipeline::hiding_vk()
    )
    .is_err());

    if let Some(record) = std::env::var_os("EID_RECORD") {
        record_runs(Path::new(&record));
    }
}

/// One chain proven at the ambient thread count, for the recorder (which
/// measures this process's peak memory from outside).
fn one_run(frozen: &dyn Artifacts, chain_name: &str) {
    let pool = Merged::new(&[frozen, &noir_zk_backend::kernels::Kernels]);
    let chain = chains()
        .into_iter()
        .find(|c| c["name"] == chain_name)
        .unwrap();
    let name = |k: &str| chain[k].as_str().unwrap();
    let (d, s, e) = (
        chain_toml(name("dsc")),
        chain_toml(name("sod")),
        chain_toml(name("document")),
    );
    let start = std::time::Instant::now();
    let (proof, _) = fold(&pool, &chain, &d, &s, &e).unwrap();
    let seconds = start.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({ "seconds": seconds, "proof_bytes": proof.to_bytes().len() })
    );
}

/// noir-zk's kernels' Chonk gates (`bb gates --scheme chonk` on the bundled
/// kernels of the pinned revision), so COSTS.md can add them to a document.
const KERNEL_GATES: [(&str, u64); 4] = [
    ("kernel_init", 14_056),
    ("kernel_step", 29_965),
    ("kernel_tail", 17_533),
    ("kernel_hiding", 39_007),
];

/// Proves every chain in a child process per thread count (so each peak is
/// its own) and writes `docs/data/fold-times.json`.
fn record_runs(path: &Path) {
    let sizes: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("docs/data/circuit-sizes.json")).unwrap(),
    )
    .unwrap();
    let gates = |label: &str| sizes[label]["gates"].as_u64().unwrap();
    let threads: Vec<String> = std::env::var("EID_THREADS")
        .unwrap_or_else(|_| "4".into())
        .split(',')
        .map(str::to_string)
        .collect();
    let exe = std::env::current_exe().unwrap();
    let mut runs = vec![];
    for chain in chains() {
        let name = |k: &str| chain[k].as_str().unwrap();
        let steps = [
            gates(name("dsc")),
            gates(name("sod")),
            gates(name("document")),
        ];
        let kernels = KERNEL_GATES[0].1 + 2 * KERNEL_GATES[1].1 + KERNEL_GATES[3].1;
        let total = steps.iter().sum::<u64>() + kernels;
        let max = steps.iter().copied().max().unwrap().max(KERNEL_GATES[3].1);
        for t in &threads {
            // `/usr/bin/time -l` (macOS) / `-v` (GNU) reports the child's peak
            // resident set; the child prints its own timing.
            let out = std::process::Command::new("/usr/bin/time")
                .arg(if cfg!(target_os = "macos") {
                    "-l"
                } else {
                    "-v"
                })
                .arg(&exe)
                .args(["--exact", "folds_and_verifies_every_chain", "--nocapture"])
                .env("EID_ONE", name("name"))
                .env("HARDWARE_CONCURRENCY", t)
                .env_remove("EID_RECORD")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let line = String::from_utf8_lossy(&out.stdout)
                .lines()
                .find(|l| l.starts_with('{'))
                .unwrap()
                .to_string();
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            let peak: u64 = stderr
                .lines()
                .find(|l| l.contains("maximum resident set size"))
                .and_then(|l| l.split_whitespace().find_map(|w| w.parse::<u64>().ok()))
                .unwrap();
            // macOS reports bytes, GNU time kilobytes.
            let peak = if cfg!(target_os = "macos") {
                peak
            } else {
                peak * 1024
            };
            eprintln!("{} @ {t} threads: {v}, peak {peak} bytes", name("name"));
            runs.push(serde_json::json!({
                "chain": name("name"),
                "threads": t.parse::<u64>().unwrap(),
                "seconds": (v["seconds"].as_f64().unwrap() * 100.0).round() / 100.0,
                "peak_bytes": peak,
                "proof_bytes": v["proof_bytes"],
                "total_gates": total,
                "max_gates": max,
            }));
        }
    }
    let manifest =
        std::fs::read_to_string(root().join("rust/eid-circuits/circuits/manifest.toml")).unwrap();
    let pin = |k: &str| {
        manifest
            .lines()
            .find_map(|l| {
                l.strip_prefix(&format!("{k} = \""))
                    .map(|v| v.trim_end_matches('"').to_string())
            })
            .unwrap()
    };
    let out = serde_json::json!({
        "machine": std::env::var("EID_MACHINE").unwrap_or_default(),
        "bb": pin("bb"),
        "nargo": pin("noir"),
        "noir_zk": "dd2d33f",
        "date": std::env::var("EID_DATE").unwrap_or_else(|_| "2026-09-29".into()),
        "kernels": KERNEL_GATES.iter().map(|(k, g)| ((*k).to_string(), serde_json::json!(g))).collect::<serde_json::Map<_, _>>(),
        "runs": runs,
    });
    std::fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&out).unwrap()),
    )
    .unwrap();
    eprintln!("wrote {}", path.display());
}
