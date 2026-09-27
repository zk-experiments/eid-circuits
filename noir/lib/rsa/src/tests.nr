//! Negative cases. Positive cases are the generated tests in vectors.nr (real
//! certificate signatures); these mutate one of them at a time.

use crate::{DIGEST_INFO_SHA256, DIGEST_INFO_SHA512, verify_pkcs1v15, verify_pss};
use crate::vectors::{
    PKCS1_SHA256_2048_IS_EXPONENT, PKCS1_SHA256_2048_IS_MODULUS, PKCS1_SHA256_2048_IS_REDC,
    PKCS1_SHA256_2048_IS_SIGNATURE, PKCS1_SHA256_2048_IS_TBS, PSS_SHA256_S32_3072_CZ_EXPONENT,
    PSS_SHA256_S32_3072_CZ_MODULUS, PSS_SHA256_S32_3072_CZ_REDC, PSS_SHA256_S32_3072_CZ_SIGNATURE,
    PSS_SHA256_S32_3072_CZ_TBS,
};
use eid_hash::{Sha256, sha256_var};

fn pkcs1_digest() -> [u8; 32] {
    sha256_var(PKCS1_SHA256_2048_IS_TBS, PKCS1_SHA256_2048_IS_TBS.len())
}

fn pss_digest() -> [u8; 32] {
    sha256_var(PSS_SHA256_S32_3072_CZ_TBS, PSS_SHA256_S32_3072_CZ_TBS.len())
}

#[test(should_fail_with = "RSA PKCS#1 v1.5 signature mismatch")]
fn pkcs1_rejects_tampered_signature() {
    let mut sig = PKCS1_SHA256_2048_IS_SIGNATURE;
    sig[255] ^= 1;
    verify_pkcs1v15::<18, 2048, 17, 32, 19>(
        PKCS1_SHA256_2048_IS_MODULUS,
        PKCS1_SHA256_2048_IS_REDC,
        PKCS1_SHA256_2048_IS_EXPONENT,
        sig,
        pkcs1_digest(),
        DIGEST_INFO_SHA256,
    );
}

#[test(should_fail_with = "RSA PKCS#1 v1.5 signature mismatch")]
fn pkcs1_rejects_other_message() {
    let mut digest = pkcs1_digest();
    digest[0] ^= 1;
    verify_pkcs1v15::<18, 2048, 17, 32, 19>(
        PKCS1_SHA256_2048_IS_MODULUS,
        PKCS1_SHA256_2048_IS_REDC,
        PKCS1_SHA256_2048_IS_EXPONENT,
        PKCS1_SHA256_2048_IS_SIGNATURE,
        digest,
        DIGEST_INFO_SHA256,
    );
}

#[test(should_fail_with = "RSA PKCS#1 v1.5 signature mismatch")]
fn pkcs1_rejects_other_digest_algorithm() {
    // Same 32-byte digest, but the DigestInfo claims SHA-512.
    verify_pkcs1v15::<18, 2048, 17, 32, 19>(
        PKCS1_SHA256_2048_IS_MODULUS,
        PKCS1_SHA256_2048_IS_REDC,
        PKCS1_SHA256_2048_IS_EXPONENT,
        PKCS1_SHA256_2048_IS_SIGNATURE,
        pkcs1_digest(),
        DIGEST_INFO_SHA512,
    );
}

#[test(should_fail_with = "RSA PKCS#1 v1.5 signature mismatch")]
fn rejects_other_exponent() {
    verify_pkcs1v15::<18, 2048, 17, 32, 19>(
        PKCS1_SHA256_2048_IS_MODULUS,
        PKCS1_SHA256_2048_IS_REDC,
        65539,
        PKCS1_SHA256_2048_IS_SIGNATURE,
        pkcs1_digest(),
        DIGEST_INFO_SHA256,
    );
}

#[test(should_fail_with = "RSA exponent must be odd")]
fn rejects_even_exponent() {
    verify_pkcs1v15::<18, 2048, 17, 32, 19>(
        PKCS1_SHA256_2048_IS_MODULUS,
        PKCS1_SHA256_2048_IS_REDC,
        65536,
        PKCS1_SHA256_2048_IS_SIGNATURE,
        pkcs1_digest(),
        DIGEST_INFO_SHA256,
    );
}

#[test(should_fail_with = "exponent does not fit E_BITS")]
fn rejects_exponent_wider_than_e_bits() {
    verify_pkcs1v15::<18, 2048, 16, 32, 19>(
        PKCS1_SHA256_2048_IS_MODULUS,
        PKCS1_SHA256_2048_IS_REDC,
        PKCS1_SHA256_2048_IS_EXPONENT,
        PKCS1_SHA256_2048_IS_SIGNATURE,
        pkcs1_digest(),
        DIGEST_INFO_SHA256,
    );
}

#[test(should_fail)]
fn rejects_signature_not_below_modulus() {
    verify_pkcs1v15::<18, 2048, 17, 32, 19>(
        PKCS1_SHA256_2048_IS_MODULUS,
        PKCS1_SHA256_2048_IS_REDC,
        PKCS1_SHA256_2048_IS_EXPONENT,
        [0xff; 256],
        pkcs1_digest(),
        DIGEST_INFO_SHA256,
    );
}

#[test(should_fail_with = "modulus must have its top bit set")]
fn rejects_short_modulus() {
    let mut modulus = PKCS1_SHA256_2048_IS_MODULUS;
    modulus[0] = 0x7f;
    verify_pkcs1v15::<18, 2048, 17, 32, 19>(
        modulus,
        PKCS1_SHA256_2048_IS_REDC,
        PKCS1_SHA256_2048_IS_EXPONENT,
        PKCS1_SHA256_2048_IS_SIGNATURE,
        pkcs1_digest(),
        DIGEST_INFO_SHA256,
    );
}

#[test(should_fail_with = "RSA-PSS signature mismatch")]
fn pss_rejects_other_message() {
    let mut digest = pss_digest();
    digest[31] ^= 0x80;
    verify_pss::<Sha256, 26, 3072, 17, 32, 32>(
        PSS_SHA256_S32_3072_CZ_MODULUS,
        PSS_SHA256_S32_3072_CZ_REDC,
        PSS_SHA256_S32_3072_CZ_EXPONENT,
        PSS_SHA256_S32_3072_CZ_SIGNATURE,
        digest,
    );
}

// A salt one byte shorter moves the expected separator one byte right, so the
// real 0x01 separator falls inside the padding string.
#[test(should_fail_with = "PSS padding string must be zero")]
fn pss_rejects_shorter_salt_length() {
    verify_pss::<Sha256, 26, 3072, 17, 32, 31>(
        PSS_SHA256_S32_3072_CZ_MODULUS,
        PSS_SHA256_S32_3072_CZ_REDC,
        PSS_SHA256_S32_3072_CZ_EXPONENT,
        PSS_SHA256_S32_3072_CZ_SIGNATURE,
        pss_digest(),
    );
}

// A salt one byte longer moves the expected separator one byte left, onto the
// last (zero) padding byte.
#[test(should_fail_with = "PSS separator must be 0x01")]
fn pss_rejects_longer_salt_length() {
    verify_pss::<Sha256, 26, 3072, 17, 32, 33>(
        PSS_SHA256_S32_3072_CZ_MODULUS,
        PSS_SHA256_S32_3072_CZ_REDC,
        PSS_SHA256_S32_3072_CZ_EXPONENT,
        PSS_SHA256_S32_3072_CZ_SIGNATURE,
        pss_digest(),
    );
}

#[test(should_fail)]
fn pss_rejects_tampered_signature() {
    let mut sig = PSS_SHA256_S32_3072_CZ_SIGNATURE;
    sig[100] ^= 1;
    verify_pss::<Sha256, 26, 3072, 17, 32, 32>(
        PSS_SHA256_S32_3072_CZ_MODULUS,
        PSS_SHA256_S32_3072_CZ_REDC,
        PSS_SHA256_S32_3072_CZ_EXPONENT,
        sig,
        pss_digest(),
    );
}
