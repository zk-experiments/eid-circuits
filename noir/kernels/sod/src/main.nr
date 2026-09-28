//! Folds the DSC kernel and the SOD step. The SOD step's first output must be
//! the DSC step's commitment `c_A`; its second, `c_B`, becomes the link.

use eid_kernel::{
    check_vk, PROOF_TYPE_HN, ROLE_KERNEL_DSC, ROLE_SOD, S_LINK, S_VK_TREE_ROOT, STATE_FIELDS, Vk,
};

fn main(
    prev: call_data(0) [Field; STATE_FIELDS],
    step: call_data(1) [Field; 2],
    prev_vk: Vk,
    step_vk: Vk,
) -> return_data [Field; STATE_FIELDS] {
    let root = prev[S_VK_TREE_ROOT];
    let hk = check_vk(root, ROLE_KERNEL_DSC, prev_vk);
    std::verify_proof_with_type(prev_vk.key, [], [], hk, PROOF_TYPE_HN);
    let hs = check_vk(root, ROLE_SOD, step_vk);
    std::verify_proof_with_type(step_vk.key, [], [], hs, PROOF_TYPE_HN);
    assert_eq(step[0], prev[S_LINK], "SOD step does not continue the DSC step");
    let mut s = prev;
    s[S_LINK] = step[1];
    s
}
