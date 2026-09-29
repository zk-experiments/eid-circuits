//! Generates the bindings of the frozen circuits (`circuits/manifest.toml`,
//! `resources/`, written by `noir-zk freeze`) and their families (declared
//! in the manifest), and with feature `bundled` compiles circuits from the
//! shipped Noir source and embeds their bytecode.
//!
//! `bundled` needs nargo at the manifest's Noir version (`$NARGO`, as `mise
//! env` sets it, else `nargo` on `PATH`; `mise run install:zk-toolchain`
//! installs it) and network access for the Noir libraries' git dependencies.
//! `EID_CIRCUITS_BUNDLE` picks the circuits: pack names from
//! `circuits/packs.toml`, comma-separated (default: every pack), or `none`.
//! Every compiled circuit must hash to its pin, or the build fails: the
//! source reproduces the frozen bytecode exactly.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    std::fs::write(
        out.join("circuits.rs"),
        noir_zk_codegen::generate_registry(&dir),
    )
    .unwrap_or_else(|e| panic!("circuits.rs: {e}"));
    println!("cargo:rerun-if-changed=circuits/manifest.toml");
    println!("cargo:rerun-if-changed=resources");
    if std::env::var_os("CARGO_FEATURE_BUNDLED").is_some() {
        bundle(&dir, &out);
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap_or_else(|e| panic!("{}: {e}", to.display()));
    for entry in std::fs::read_dir(from).unwrap_or_else(|e| panic!("{}: {e}", from.display())) {
        let path = entry.unwrap_or_else(|e| panic!("{e}")).path();
        let name = path.file_name().unwrap_or_default();
        if name == "target" {
            continue;
        }
        if path.is_dir() {
            copy_dir(&path, &to.join(name));
        } else {
            std::fs::copy(&path, to.join(name))
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }
}

fn bundle(dir: &Path, out: &Path) {
    println!("cargo:rerun-if-env-changed=EID_CIRCUITS_BUNDLE");
    println!("cargo:rerun-if-env-changed=NARGO");
    println!("cargo:rerun-if-changed=circuits/packs.toml");
    let manifest: toml::Table = toml::from_str(&read(&dir.join("circuits/manifest.toml")))
        .unwrap_or_else(|e| panic!("manifest.toml: {e}"));
    let packs: toml::Table = toml::from_str(&read(&dir.join("circuits/packs.toml")))
        .unwrap_or_else(|e| panic!("packs.toml: {e}"));

    let choice = std::env::var("EID_CIRCUITS_BUNDLE").unwrap_or_default();
    let names: Vec<String> = match choice.trim() {
        "" => packs
            .iter()
            .filter(|(_, p)| p.get("circuits").is_some())
            .map(|(n, _)| n.clone())
            .collect(),
        "none" => vec![],
        list => list.split(',').map(|s| s.trim().to_string()).collect(),
    };
    let mut labels: BTreeSet<String> = BTreeSet::new();
    for name in &names {
        let circuits = packs
            .get(name)
            .and_then(|p| p.get("circuits"))
            .and_then(|c| c.as_array())
            .unwrap_or_else(|| {
                panic!("EID_CIRCUITS_BUNDLE: no pack {name:?} in circuits/packs.toml")
            });
        labels.extend(
            circuits
                .iter()
                .filter_map(|l| l.as_str().map(str::to_string)),
        );
    }

    // label -> (version, pinned sha256)
    let pins: Vec<(String, String, String)> = manifest["circuit"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["status"].as_str() == Some("active"))
        .filter_map(|c| {
            Some((
                c["label"].as_str()?.to_string(),
                c["version"].as_str()?.to_string(),
                c["bytecode_sha256"].as_str()?.to_string(),
            ))
        })
        .filter(|(l, ..)| labels.contains(l))
        .collect();

    let mut code = String::from(
        "/// Embedded bytecode assets: (`<label>@<version>.b64`, base64 bytecode).\n\
         pub static ASSETS: &[(&str, &[u8])] = &[\n",
    );
    if !pins.is_empty() {
        let noir = manifest["noir"].as_str().unwrap_or_default();
        let nargo = std::env::var("NARGO").unwrap_or_else(|_| "nargo".into());
        let version = Command::new(&nargo)
            .arg("--version")
            .output()
            .unwrap_or_else(|e| {
                panic!("bundled: {nargo}: {e} (install it: mise run install:zk-toolchain)")
            });
        let version = String::from_utf8_lossy(&version.stdout);
        assert!(
            version.contains(&format!("nargo version = {noir}")),
            "bundled: {nargo} is not nargo {noir}: {version}"
        );
        // nargo writes target/ into the outermost Noir workspace above the
        // current directory, and OUT_DIR may sit inside one (this repository),
        // so compile a copy under the system temp directory.
        let src = std::env::temp_dir().join(format!(
            "eid-circuits-noir-{}",
            hex::encode(&Sha256::digest(out.to_string_lossy().as_bytes())[..8])
        ));
        let _ = std::fs::remove_dir_all(&src);
        copy_dir(&dir.join("noir"), &src.join("noir"));
        std::fs::copy(dir.join("Nargo.toml"), src.join("Nargo.toml"))
            .unwrap_or_else(|e| panic!("Nargo.toml: {e}"));
        for (label, ..) in &pins {
            let status = Command::new(&nargo)
                .args(["compile", "--silence-warnings", "--package", label])
                .current_dir(&src)
                .status()
                .unwrap_or_else(|e| panic!("bundled: {nargo}: {e}"));
            assert!(status.success(), "bundled: nargo compile {label} failed");
        }
        let assets = out.join("bundled");
        std::fs::create_dir_all(&assets).unwrap_or_else(|e| panic!("{e}"));
        for (label, version, pin) in &pins {
            let artifact: serde_json::Value =
                serde_json::from_str(&read(&src.join(format!("target/{label}.json"))))
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
            let bytecode = artifact["bytecode"].as_str().unwrap_or_default();
            let got = hex::encode(Sha256::digest(bytecode.as_bytes()));
            assert!(
                &got == pin,
                "bundled: {label} compiled to {got}, but its pin is {pin}: the source doesn't reproduce the frozen circuit"
            );
            let asset = format!("{label}@{version}.b64");
            std::fs::write(assets.join(&asset), bytecode).unwrap_or_else(|e| panic!("{e}"));
            code.push_str(&format!(
                "    ({asset:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bundled/{asset}\"))),\n"
            ));
        }
    }
    code.push_str("];\n");
    if !pins.is_empty() {
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!(
            "eid-circuits-noir-{}",
            hex::encode(&Sha256::digest(out.to_string_lossy().as_bytes())[..8])
        )));
    }
    std::fs::write(out.join("bundled.rs"), code).unwrap_or_else(|e| panic!("bundled.rs: {e}"));
}
