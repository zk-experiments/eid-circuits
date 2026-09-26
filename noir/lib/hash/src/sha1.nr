//! SHA-1 (FIPS 180-4 §6.1) over the first `len` bytes of a fixed buffer.
//!
//! SHA-1 is broken for collision resistance; it is here only because several
//! issuers still sign CSCA/DSC certificates and SODs with it. A circuit that
//! accepts SHA-1 accepts that weakness for those documents.
//!
//! Construction: the buffer is padded as if the message were `len` bytes
//! (0x80, zeros, 64-bit big-endian bit length), every one of the
//! `MAX_BLOCKS = (N + 8) / 64 + 1` blocks is compressed, and the state after
//! the message's last block is selected. Bytes at or past `len` never reach
//! the compression function.

global H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

fn rotl(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

/// Addition mod 2^32 (the u64 sum is truncated by the cast).
fn add(a: u32, b: u32) -> u32 {
    (a as u64 + b as u64) as u32
}

fn compress(state: [u32; 5], block: [u8; 64]) -> [u32; 5] {
    let mut w: [u32; 80] = [0; 80];
    for t in 0..16 {
        w[t] = ((block[4 * t] as u32) << 24)
            | ((block[4 * t + 1] as u32) << 16)
            | ((block[4 * t + 2] as u32) << 8)
            | (block[4 * t + 3] as u32);
    }
    for t in 16..80 {
        w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    for t in 0..80 {
        let (f, k) = if t < 20 {
            ((b & c) | (!b & d), 0x5A827999)
        } else if t < 40 {
            (b ^ c ^ d, 0x6ED9EBA1)
        } else if t < 60 {
            ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
        } else {
            (b ^ c ^ d, 0xCA62C1D6)
        };
        let temp = add(add(add(rotl(a, 5), f), add(e, k)), w[t]);
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }
    [add(state[0], a), add(state[1], b), add(state[2], c), add(state[3], d), add(state[4], e)]
}

/// Byte `i` of the message padded as a `len`-byte message whose padding ends
/// at byte `end` (a multiple of 64). `data` is `msg[i]` when `i < len`.
fn pad(data: u8, len: u32, end: u32, i: u32) -> u8 {
    let bits: u64 = (len as u64) * 8;
    if i < len {
        data
    } else if i == len {
        0x80
    } else if (i + 8 >= end) & (i < end) {
        let shift = (end - 1 - i) * 8;
        ((bits >> (shift as u64)) & 0xff) as u8
    } else {
        0
    }
}

pub(crate) fn digest<let N: u32>(msg: [u8; N], len: u32) -> [u8; 20] {
    assert(len <= N, "message length exceeds buffer");
    // Blocks the padded message occupies: ceil((len + 9) / 64).
    let blocks = (len + 8) / 64 + 1;
    let end = blocks * 64;
    let mut state = H0;
    let mut result = H0;
    for b in 0..((N + 8) / 64 + 1) {
        let mut block: [u8; 64] = [0; 64];
        for j in 0..64 {
            let i = b * 64 + j;
            // Compile-time clamp keeps the index in bounds; a clamped byte is
            // never used because i >= N >= len.
            let idx = if i < N { i } else { N - 1 };
            block[j] = pad(msg[idx], len, end, i);
        }
        state = compress(state, block);
        if b + 1 == blocks {
            result = state;
        }
    }
    let mut out: [u8; 20] = [0; 20];
    for i in 0..5 {
        out[4 * i] = (result[i] >> 24) as u8;
        out[4 * i + 1] = (result[i] >> 16) as u8;
        out[4 * i + 2] = (result[i] >> 8) as u8;
        out[4 * i + 3] = result[i] as u8;
    }
    out
}
