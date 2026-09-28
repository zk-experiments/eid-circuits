//! Folds the SOD kernel and the envelope step, whose databus output is
//! `eid_steps::envelope::flatten`: date, context, the viewer key, `c_B` (at 4),
//! the envelope, the scope and the nullifier. `c_B` must be the SOD step's
//! link.

use eid_kernel::{
    check_vk, PROOF_TYPE_HN, ROLE_ENVELOPE, ROLE_KERNEL_SOD, S_ENVELOPE, S_LINK, S_NULLIFIER,
    S_SCOPE, S_VK_TREE_ROOT, STATE_FIELDS, Vk,
};

fn main(
    prev: call_data(0) [Field; STATE_FIELDS],
    step: call_data(1) [Field; 16],
    prev_vk: Vk,
    step_vk: Vk,
) -> return_data [Field; STATE_FIELDS] {
    let root = prev[S_VK_TREE_ROOT];
    let hk = check_vk(root, ROLE_KERNEL_SOD, prev_vk);
    std::verify_proof_with_type(prev_vk.key, [], [], hk, PROOF_TYPE_HN);
    let hs = check_vk(root, ROLE_ENVELOPE, step_vk);
    std::verify_proof_with_type(step_vk.key, [], [], hs, PROOF_TYPE_HN);
    assert_eq(step[4], prev[S_LINK], "envelope step does not continue the SOD step");
    let mut s = prev;
    s[S_LINK] = 0;
    // date, context, viewer
    for i in 0..4 {
        s[S_ENVELOPE + i] = step[i];
    }
    // E, wrapped key, ciphertext
    for i in 0..9 {
        s[S_ENVELOPE + 4 + i] = step[5 + i];
    }
    s[S_SCOPE] = step[14];
    s[S_NULLIFIER] = step[15];
    s
}
