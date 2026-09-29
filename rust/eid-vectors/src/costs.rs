//! Generates `docs/COSTS.md`: what each country's documents cost to prove,
//! from the registry fixtures (who signs with what, how large their
//! certificates are), the Chonk gate counts in `docs/data/circuit-sizes.json`
//! and the folded document proofs measured in `docs/data/fold-times.json`
//! (`mise run fold:record`: the test-only pipeline `[dsc, sod, document]`
//! through noir-zk's kernels, whose gates the file records with the runs).

use crate::{fixtures, root};
use anyhow::{Context, Result};
use csca_registry::cert::Cert;
use csca_registry::masterlist;
use eid_prover::config::{bucket, document_package, BUCKETS};
use eid_prover::config::{Config, DSC_CONFIGS};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

/// Report date: CSCA keys valid (and inside their private-key usage period)
/// on 2026-09-27T00:00:00Z count as currently issuing DSCs.
const REPORT_DATE: i64 = 1_790_467_200;

/// Phone time = laptop time with 4 threads × factor. These are assumptions,
/// not measurements; replace them after measuring one circuit on a device.
const FLAGSHIP_FACTOR: f64 = 2.0;
const MIDRANGE_FACTOR: f64 = 6.0;

/// Least-squares `y = a·x + b`.
fn fit(points: &[(f64, f64)]) -> (f64, f64) {
    let n = f64::from(u32::try_from(points.len()).unwrap_or(u32::MAX));
    let (sx, sy) = points
        .iter()
        .fold((0.0, 0.0), |(a, b), (x, y)| (a + x, b + y));
    let sxx: f64 = points.iter().map(|(x, _)| x * x).sum();
    let sxy: f64 = points.iter().map(|(x, y)| x * y).sum();
    let a = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    (a, (sy - a * sx) / n)
}

fn secs(s: f64) -> String {
    format!("{s:.1} s")
}

fn mib(bytes: f64) -> String {
    format!("{:.0} MiB", bytes / 1_048_576.0)
}

pub(crate) fn report() -> Result<String> {
    let sizes: HashMap<String, Value> = serde_json::from_str(&std::fs::read_to_string(
        root().join("docs/data/circuit-sizes.json"),
    )?)?;
    let times: Value = serde_json::from_str(&std::fs::read_to_string(
        root().join("docs/data/fold-times.json"),
    )?)?;
    let runs = times["runs"].as_array().context("runs")?;
    let max_threads = runs
        .iter()
        .filter_map(|r| r["threads"].as_u64())
        .max()
        .unwrap_or(4);
    let gates = |pkg: &str| sizes.get(pkg).and_then(|v| v["gates"].as_f64());
    let (mut pts_all, mut pts_4, mut pts_mem) = (vec![], vec![], vec![]);
    for r in runs {
        let (Some(t), Some(th), Some(total), Some(largest)) = (
            r["seconds"].as_f64(),
            r["threads"].as_u64(),
            r["total_gates"].as_f64(),
            r["max_gates"].as_f64(),
        ) else {
            continue;
        };
        if th == 4 {
            pts_4.push((total, t));
        } else {
            pts_all.push((total, t));
        }
        if let Some(p) = r["peak_bytes"].as_f64() {
            pts_mem.push((largest, p));
        }
    }
    let (a4, b4) = fit(&pts_4);
    let (aa, ba) = fit(&pts_all);
    let (am, bm) = fit(&pts_mem);
    // noir-zk's generic kernels, as the fold test recorded them: a three-app
    // pipeline folds kernel_init, two kernel_steps and kernel_hiding.
    let kg = |k: &str| times["kernels"][k].as_f64().unwrap_or(0.0);
    let kernels: Vec<(&str, f64)> = vec![
        ("kernel_init", kg("kernel_init")),
        ("2 \u{d7} kernel_step", 2.0 * kg("kernel_step")),
        ("kernel_hiding", kg("kernel_hiding")),
    ];
    let kernel_total: f64 = kernels.iter().map(|(_, g)| g).sum();
    let kernel_max = [kg("kernel_init"), kg("kernel_step"), kg("kernel_hiding")]
        .into_iter()
        .fold(0.0, f64::max);
    // A document whose DSC signs with the CSCA's configuration and whose LDS
    // uses that configuration's hash throughout, in the 512-byte eContent
    // bucket: (total gates, largest circuit).
    let document = |config: Config, t: usize| -> Option<(f64, f64)> {
        let a = gates(&config.step_package("dsc", t))?;
        let b = gates(&config.step_package("sod", t))?;
        let h = config.hash();
        let c = gates(&document_package(h, h, 512))?;
        Some((a + b + c + kernel_total, a.max(b).max(c).max(kernel_max)))
    };

    // Certificates, their TBS sizes and issuers, from the fixture master lists.
    let mut certs: HashMap<String, Cert> = HashMap::new();
    for entry in std::fs::read_dir(fixtures().join("sources"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "ml") {
            let cc: String = path
                .file_name()
                .map(|f| f.to_string_lossy().chars().take(2).collect())
                .unwrap_or_default();
            for c in masterlist::load(&std::fs::read(&path)?, &cc.to_uppercase())?.certs {
                certs.insert(c.fingerprint.clone(), c);
            }
        }
    }
    let reg = crate::steps::registry()?;
    let tbs_len = |c: &Cert| csca_registry::der::signed_parts(&c.der).map(|p| p.0.len());

    // Per country: current configurations and certificate sizes.
    struct Row {
        sizes: Vec<usize>,
        issuers: BTreeSet<String>,
    }
    let mut current: BTreeMap<(String, String), (Config, Row)> = BTreeMap::new();
    let mut all_countries: BTreeSet<String> = BTreeSet::new();
    for e in &reg.certificates {
        all_countries.insert(e.country.clone());
        let (Some(issuer_fp), "verified") = (e.issuer_fingerprint.as_ref(), e.chain.as_str())
        else {
            continue;
        };
        let (Some(cert), Some(issuer)) = (certs.get(&e.fingerprint), certs.get(issuer_fp)) else {
            continue;
        };
        let usable_until = issuer
            .private_key_usage
            .and_then(|(_, to)| to)
            .unwrap_or(issuer.not_after)
            .min(issuer.not_after);
        if usable_until < REPORT_DATE {
            continue;
        }
        let Ok(key) = issuer.key.clone() else {
            continue;
        };
        let Some(config) = Config::of(cert, &key) else {
            continue;
        };
        let Some(len) = tbs_len(cert) else { continue };
        let label = config.label();
        let entry = current.entry((e.country.clone(), label)).or_insert((
            config,
            Row {
                sizes: vec![],
                issuers: BTreeSet::new(),
            },
        ));
        entry.1.sizes.push(len);
        entry.1.issuers.insert(issuer_fp.clone());
    }

    let mut out = String::new();
    writeln!(out, "# Proving costs\n")?;
    writeln!(out, "Generated by `eid-vectors costs` (`rust/eid-vectors/src/costs.rs`) from the registry fixtures (DE and IT master lists) and the measurements in `docs/data/`. Do not edit by hand; re-measure with `mise run fold:record` and regenerate.\n")?;
    writeln!(out, "## What is measured\n")?;
    writeln!(out, "- **A document proof** is one Chonk proof: the DSC, SOD and document steps folded by noir-zk's generic kernels (`kernel_init`, two `kernel_step`s, `kernel_hiding`) in the test-only pipeline `[dsc, sod, document]` ([FOLDING.md](FOLDING.md)). A real pipeline adds its envelope app and whatever else it folds, one `kernel_step` each.")?;
    writeln!(out, "- **Gates** come from `bb gates --scheme chonk` for every circuit (`docs/data/circuit-sizes.json`).")?;
    writeln!(
        out,
        "- **Proving time and peak memory** come from `mise run fold:record` (`rust/eid-circuits/tests/fold.rs`, in-process through noir-zk's `PipelineFold`) on {} (bb {}, nargo {}, {}), with {max_threads} threads and with 4 threads, for the synthetic documents of `noir/circuits/chains.json`. Every proof was verified. Other documents are estimated (\u{2248}) with least-squares fits: time against a document's total gates (4 threads `{:.2} s per million gates + {:.2} s`, {max_threads} threads `{:.2} s/Mgate + {:.2} s`), and peak memory against its largest circuit (`{:.0} bytes per gate {:+.0} MiB`), since Chonk proves one circuit at a time.",
        times["machine"].as_str().unwrap_or("?"),
        times["bb"].as_str().unwrap_or("?"),
        times["nargo"].as_str().unwrap_or("?"),
        times["date"].as_str().unwrap_or("?"),
        a4 * 1e6, b4, aa * 1e6, ba, am, bm / 1_048_576.0,
    )?;
    writeln!(out, "- **Per-country documents are an assumption:** the master lists hold CSCAs only, so each country's DSC is assumed to sign with its CSCA's configuration, and its LDS to use that configuration's hash in the 512-byte eContent bucket. Real DSC statistics (the ICAO PKD DSC list) would replace this.")?;
    writeln!(out, "- **Phone estimates are assumptions, not measurements:** laptop time with 4 threads \u{d7} {FLAGSHIP_FACTOR} for a recent flagship phone, \u{d7} {MIDRANGE_FACTOR} for a mid-range Android phone. Measure a document proof on a real device and scale these columns by the observed ratio.")?;
    writeln!(out, "- **Memory cap.** Every circuit is capped at 2 GiB of proving memory: CI fails any circuit above 858,993 gates (2 GiB at 2,500 bytes per gate).\n")?;

    writeln!(out, "## Measured documents\n")?;
    writeln!(out, "| document | total gates | largest circuit | laptop {max_threads} threads | laptop 4 threads | peak memory |")?;
    writeln!(out, "|---|---:|---:|---:|---:|---:|")?;
    let mut by_chain: BTreeMap<String, (f64, f64, Option<f64>, Option<f64>, f64)> = BTreeMap::new();
    for r in runs {
        let name = r["chain"].as_str().unwrap_or("?").to_string();
        let e = by_chain.entry(name).or_insert((
            r["total_gates"].as_f64().unwrap_or(0.0),
            r["max_gates"].as_f64().unwrap_or(0.0),
            None,
            None,
            0.0,
        ));
        if r["threads"].as_u64() == Some(4) {
            e.3 = r["seconds"].as_f64();
        } else {
            e.2 = r["seconds"].as_f64();
        }
        e.4 = e.4.max(r["peak_bytes"].as_f64().unwrap_or(0.0));
    }
    for (name, (total, largest, ta, t4, peak)) in &by_chain {
        writeln!(
            out,
            "| {name} | {:.0}k | {:.0}k | {} | {} | {} |",
            total / 1000.0,
            largest / 1000.0,
            ta.map_or("?".into(), secs),
            t4.map_or("?".into(), secs),
            mib(*peak),
        )?;
    }

    writeln!(out, "\n## By country\n")?;
    writeln!(out, "One row per CSCA signing configuration in use on 2026-09-27 (a CSCA certificate that is valid and inside its private-key usage period, signing certificates with that scheme). The DSC certificate size is not in the master lists; the CSCA certificates' own `TBSCertificate` sizes are shown as the closest proxy, and the bucket is the one their median fits.\n")?;
    writeln!(out, "| country | CSCA key \u{b7} scheme | cert size median / max (bytes) | DSC circuit | document gates | laptop 4 threads | peak memory | phone flagship / mid-range |")?;
    writeln!(out, "|---|---|---:|---|---:|---:|---:|---:|")?;
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for ((cc, label), (config, row)) in &current {
        let mut s = row.sizes.clone();
        s.sort_unstable();
        let median = s[s.len() / 2];
        let max = *s.last().unwrap_or(&median);
        let t = bucket(median).unwrap_or(BUCKETS[BUCKETS.len() - 1]);
        let Some((total, largest)) = document(*config, t) else {
            continue;
        };
        let t4 = a4 * total + b4;
        writeln!(
            out,
            "| {cc} | {label} | {median} / {max} | `{}` | \u{2248} {:.0}k | \u{2248} {} | \u{2248} {} | \u{2248} {} / {} |",
            config.package(t),
            total / 1000.0,
            secs(t4),
            mib(am * largest + bm),
            secs(t4 * FLAGSHIP_FACTOR),
            secs(t4 * MIDRANGE_FACTOR),
        )?;
        covered.insert(cc.clone());
    }
    let missing: Vec<&String> = all_countries
        .iter()
        .filter(|c| !covered.contains(*c))
        .collect();
    writeln!(out, "\n{} countries have a current configuration above. {} countries in the registry have none: every CSCA key in the data has expired or left its usage period, or its only certificates have an issuer missing from the lists: {}.\n", covered.len(), missing.len(), missing.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", "))?;

    writeln!(out, "## By configuration\n")?;
    writeln!(out, "Every signing configuration and `TBSCertificate` bucket, with the DSC and SOD step circuits and the estimated document proof (same assumption as above).\n")?;
    writeln!(out, "| configuration | bucket | DSC step | SOD step | document gates | laptop {max_threads} threads | laptop 4 threads | peak memory |")?;
    writeln!(out, "|---|---:|---:|---:|---:|---:|---:|---:|")?;
    for c in DSC_CONFIGS {
        for t in BUCKETS {
            let (Some(a), Some(b), Some((total, largest))) = (
                gates(&c.step_package("dsc", t)),
                gates(&c.step_package("sod", t)),
                document(*c, t),
            ) else {
                continue;
            };
            writeln!(
                out,
                "| {} | {t} | {:.0}k | {:.0}k | {:.0}k | \u{2248} {} | \u{2248} {} | \u{2248} {} |",
                c.label(),
                a / 1000.0,
                b / 1000.0,
                total / 1000.0,
                secs(aa * total + ba),
                secs(a4 * total + b4),
                mib(am * largest + bm),
            )?;
        }
    }
    writeln!(
        out,
        "\nnoir-zk's kernels add {:.0}k gates to every three-step document ({}); they are shared by every layer and pipeline, so a combining pipeline pays one `kernel_step` per extra app rather than a kernel of its own.",
        kernel_total / 1000.0,
        kernels
            .iter()
            .map(|(n, g)| format!("{n} {:.0}k", g / 1000.0))
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    Ok(out)
}
