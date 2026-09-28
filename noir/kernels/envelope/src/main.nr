//! Folds the SOD kernel and the envelope step, whose databus output is
//! `eid_steps::envelope::flatten`: date, context, viewers, `c_B` (at 10), the
//! hash ids, the envelope, the scope and the nullifier. `c_B` must be the SOD
//! step's link.

use eid_kernel::{
    check_vk, is_sha1, or, PROOF_TYPE_HN, ROLE_ENVELOPE, ROLE_KERNEL_SOD, S_ENVELOPE, S_LINK,
    S_NULLIFIER, S_SCOPE, S_USES_SHA1, S_VK_TREE_ROOT, STATE_FIELDS, Vk,
};

fn main(
    prev: call_data(0) [Field; STATE_FIELDS],
    step: call_data(1) [Field; 27],
    prev_vk: Vk,
    step_vk: Vk,
) -> return_data [Field; STATE_FIELDS] {
    let root = prev[S_VK_TREE_ROOT];
    let hk = check_vk(root, ROLE_KERNEL_SOD, prev_vk);
    std::verify_proof_with_type(prev_vk.key, [], [], hk, PROOF_TYPE_HN);
    let hs = check_vk(root, ROLE_ENVELOPE, step_vk);
    std::verify_proof_with_type(step_vk.key, [], [], hs, PROOF_TYPE_HN);
    assert_eq(step[10], prev[S_LINK], "envelope step does not continue the SOD step");
    let mut s = prev;
    s[S_LINK] = 0;
    s[S_USES_SHA1] = or(prev[S_USES_SHA1], or(is_sha1(step[11]), is_sha1(step[12])));
    // date, context, viewers
    for i in 0..10 {
        s[S_ENVELOPE + i] = step[i];
    }
    // E, wrapped keys, ciphertext
    for i in 0..12 {
        s[S_ENVELOPE + 10 + i] = step[13 + i];
    }
    s[S_SCOPE] = step[25];
    s[S_NULLIFIER] = step[26];
    s
}
