//! DG1: the MRZ, as `61 L 5F1F L' MRZ` (ICAO 9303 part 10 §4.7.1).

use anyhow::{bail, ensure, Context, Result};

/// Fields of DG1 the statement uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dg1 {
    /// Issuing state as written (e.g. `D<<`).
    pub issuing_state: String,
    /// Last second of the date of expiry (20YY, UTC), unix seconds.
    pub expires: i64,
}

/// Days since 1970-01-01 (H. Hinnant's days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// Parses DG1 with a TD1 (90), TD2 (72) or TD3 (88 character) MRZ.
pub fn parse_dg1(dg1: &[u8]) -> Result<Dg1> {
    ensure!(
        dg1.len() >= 5 && dg1[0] == 0x61 && dg1[2..4] == [0x5f, 0x1f],
        "not a DG1"
    );
    let len = usize::from(dg1[4]);
    ensure!(
        usize::from(dg1[1]) == len + 3 && dg1.len() == len + 5,
        "DG1 lengths are inconsistent"
    );
    let mrz = std::str::from_utf8(&dg1[5..]).context("MRZ is not ASCII")?;
    let expiry_at = match len {
        88 => 65,
        72 => 57,
        90 => 38,
        n => bail!("MRZ of {n} characters is not TD1, TD2 or TD3"),
    };
    let date = mrz.get(expiry_at..expiry_at + 6).context("MRZ too short")?;
    let n = |r: std::ops::Range<usize>| -> Result<i64> {
        date.get(r)
            .context("date")?
            .parse()
            .context("date of expiry is not numeric")
    };
    let (yy, mm, dd) = (n(0..2)?, n(2..4)?, n(4..6)?);
    ensure!(
        (1..=12).contains(&mm) && (1..=31).contains(&dd),
        "invalid date of expiry"
    );
    Ok(Dg1 {
        issuing_state: mrz[2..5].to_string(),
        expires: days_from_civil(2000 + yy, mm, dd) * 86_400 + 86_399,
    })
}

/// The ICAO code the registry commits for an MRZ issuing state (`D<<` → `DEU`),
/// as `csca_registry::country_from_mrz` does in the circuits.
pub fn registry_country(issuing_state: &str) -> String {
    if issuing_state == "D<<" {
        "DEU".to_string()
    } else {
        issuing_state.to_string()
    }
}
