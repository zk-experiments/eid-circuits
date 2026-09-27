//! Generates `docs/COSTS.md`: what each country's documents cost to prove in
//! the DSC step, from the registry fixtures (who signs with what, how large
//! their certificates are) and the committed measurements in `docs/data/`.

use crate::circuits::{Config, DSC_CONFIGS};
use crate::steps::{bucket, BUCKETS};
use crate::{fixtures, root};
use anyhow::{Context, Result};
use csca_registry::cert::Cert;
use csca_registry::masterlist;
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

struct Measured {
    seconds_all: Option<f64>,
    seconds_4: Option<f64>,
    peak: Option<f64>,
}

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
        root().join("docs/data/prove-times.json"),
    )?)?;
    let runs = times["runs"].as_array().context("runs")?;
    let max_threads = runs
        .iter()
        .filter_map(|r| r["threads"].as_u64())
        .max()
        .unwrap_or(4);
    let gates = |pkg: &str| sizes.get(pkg).and_then(|v| v["gates"].as_f64());
    let mut measured: HashMap<String, Measured> = HashMap::new();
    let (mut pts_all, mut pts_4, mut pts_mem) = (vec![], vec![], vec![]);
    for r in runs {
        let pkg = r["package"].as_str().unwrap_or_default().to_string();
        let (Some(t), Some(th), Some(g)) =
            (r["seconds"].as_f64(), r["threads"].as_u64(), gates(&pkg))
        else {
            continue;
        };
        let m = measured.entry(pkg).or_insert(Measured {
            seconds_all: None,
            seconds_4: None,
            peak: None,
        });
        if th == 4 {
            m.seconds_4 = Some(t);
            pts_4.push((g, t));
        } else {
            m.seconds_all = Some(t);
            pts_all.push((g, t));
        }
        if let Some(p) = r["peak_bytes"].as_f64() {
            m.peak = Some(p);
            pts_mem.push((g, p));
        }
    }
    let (a4, b4) = fit(&pts_4);
    let (aa, ba) = fit(&pts_all);
    let (am, bm) = fit(&pts_mem);
    // (time 4 threads, time all, peak, measured?)
    let cost = |pkg: &str| -> Option<(f64, f64, f64, bool)> {
        let g = gates(pkg)?;
        Some(match measured.get(pkg) {
            Some(Measured {
                seconds_all: Some(ta),
                seconds_4: Some(t4),
                peak: Some(p),
            }) => (*t4, *ta, *p, true),
            _ => (a4 * g + b4, aa * g + ba, am * g + bm, false),
        })
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
    writeln!(out, "Generated by `eid-vectors costs` (`rust/eid-vectors/src/costs.rs`) from the registry fixtures (DE and IT master lists) and the measurements in `docs/data/`. Do not edit by hand; re-measure with `scripts/measure-proving.sh` and regenerate.\n")?;
    writeln!(out, "## What is measured\n")?;
    writeln!(out, "- **Circuit:** the DSC step (step A in [ARCHITECTURE.md](ARCHITECTURE.md)). It parses the DSC certificate, checks the CSCA key in the registry at the DSC's `notBefore` and non-revocation, hashes the certificate and verifies the CSCA signature. The SOD and envelope steps are summarised at the end of this document.")?;
    writeln!(out, "- **Gates** come from `bb gates -t noir-recursive` for every generated circuit (`docs/data/circuit-sizes.json`).")?;
    writeln!(
        out,
        "- **Proving time and peak memory** come from `bb prove` on {} (bb {}, nargo {}, {}), with {max_threads} threads and with 4 threads, for the {} circuits that have a real-certificate `Prover.toml`. Every proof was verified. Circuits without a measurement are estimated from gates with a least-squares fit over the measured ones (marked \u{2248}): 4 threads `{:.2} s per million gates + {:.2} s`, {max_threads} threads `{:.2} s/Mgate + {:.2} s`, memory `{:.0} bytes per gate {:+.0} MiB`.",
        times["machine"].as_str().unwrap_or("?"),
        times["bb"].as_str().unwrap_or("?"),
        times["nargo"].as_str().unwrap_or("?"),
        times["date"].as_str().unwrap_or("?"),
        measured.len(),
        a4 * 1e6, b4, aa * 1e6, ba, am, bm / 1_048_576.0,
    )?;
    writeln!(out, "- **Phone estimates are assumptions, not measurements:** laptop time with 4 threads \u{d7} {FLAGSHIP_FACTOR} for a recent flagship phone, \u{d7} {MIDRANGE_FACTOR} for a mid-range Android phone. Measure one circuit on a real device (bb has iOS and Android builds) and scale these columns by the observed ratio.")?;
    writeln!(
        out,
        "- **Memory** matters as much as time on phones: several circuits peak above 1 GiB. Every circuit is capped at 2 GiB of proving memory: CI fails any circuit above 858,993 gates (2 GiB at 2,500 bytes per gate; measured 1,985\u{2013}2,418), and `scripts/measure-proving.sh` fails on a measured peak above 2 GiB.\n"
    )?;

    writeln!(out, "## By country\n")?;
    writeln!(out, "One row per CSCA signing configuration in use on 2026-09-27 (a CSCA certificate that is valid and inside its private-key usage period, signing certificates with that scheme). The DSC certificate size is not in the master lists; the CSCA certificates' own `TBSCertificate` sizes are shown as the closest proxy, and the bucket is the one their median fits.\n")?;
    writeln!(out, "| country | CSCA key \u{b7} scheme | cert size median / max (bytes) | DSC circuit | gates | laptop 4 threads | peak memory | phone flagship / mid-range |")?;
    writeln!(out, "|---|---|---:|---|---:|---:|---:|---:|")?;
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for ((cc, label), (config, row)) in &current {
        let mut s = row.sizes.clone();
        s.sort_unstable();
        let median = s[s.len() / 2];
        let max = *s.last().unwrap_or(&median);
        let t = bucket(median).unwrap_or(BUCKETS[BUCKETS.len() - 1]);
        let pkg = config.package(t);
        let Some((t4, _, peak, exact)) = cost(&pkg) else {
            continue;
        };
        let approx = if exact { "" } else { "\u{2248} " };
        writeln!(
            out,
            "| {cc} | {label} | {median} / {max} | `{pkg}` | {} | {approx}{} | {approx}{} | {approx}{} / {} |",
            gates(&pkg).map_or("?".into(), |g| format!("{:.0}k", g / 1000.0)),
            secs(t4),
            mib(peak),
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

    writeln!(out, "## By circuit\n")?;
    writeln!(out, "Every generated DSC circuit, by signing configuration and `TBSCertificate` bucket. Measured values have no mark.\n")?;
    writeln!(out, "| configuration | bucket | gates | laptop {max_threads} threads | laptop 4 threads | peak memory |")?;
    writeln!(out, "|---|---:|---:|---:|---:|---:|")?;
    for c in DSC_CONFIGS {
        for t in BUCKETS {
            let pkg = c.package(t);
            let Some((t4, ta, peak, exact)) = cost(&pkg) else {
                continue;
            };
            let approx = if exact { "" } else { "\u{2248} " };
            writeln!(
                out,
                "| {} | {t} | {} | {approx}{} | {approx}{} | {approx}{} |",
                c.label(),
                gates(&pkg).map_or("?".into(), |g| format!("{:.0}k", g / 1000.0)),
                secs(ta),
                secs(t4),
                mib(peak),
            )?;
        }
    }

    writeln!(out, "\n## The other steps\n")?;
    writeln!(out, "A document needs one proof per step: DSC (above), SOD and envelope. The SOD and envelope circuits run on synthetic documents in CI (`nargo execute`) but are not timed yet, so their times and memory below are estimated from gates with the fit above.\n")?;
    writeln!(
        out,
        "| step | circuits | gates (min \u{2013} max) | laptop 4 threads | peak memory |"
    )?;
    writeln!(out, "|---|---:|---:|---:|---:|")?;
    for (step, prefix) in [("SOD", "sod_"), ("envelope", "envelope_")] {
        let g: Vec<f64> = sizes
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .filter_map(|(_, v)| v["gates"].as_f64())
            .collect();
        let (lo, hi) = g
            .iter()
            .fold((f64::MAX, 0f64), |(l, h), x| (l.min(*x), h.max(*x)));
        if g.is_empty() {
            continue;
        }
        writeln!(
            out,
            "| {step} | {} | {:.0}k \u{2013} {:.0}k | \u{2248}{} \u{2013} {} | \u{2248}{} \u{2013} {} |",
            g.len(),
            lo / 1000.0,
            hi / 1000.0,
            secs(a4 * lo + b4),
            secs(a4 * hi + b4),
            mib(am * lo + bm),
            mib(am * hi + bm),
        )?;
    }
    writeln!(out, "\nThe three proofs are verified separately on chain; there is no aggregation proof (one recursive verification alone costs about 705k gates). See [VERIFY.md](VERIFY.md).")?;
    Ok(out)
}
