//! Tail kernel: folds the envelope kernel (Chonk's tail step) and passes the
//! state on unchanged.

use eid_kernel::{
    check_vk, PROOF_TYPE_HN_TAIL, ROLE_KERNEL_ENVELOPE, S_VK_TREE_ROOT, STATE_FIELDS, Vk,
};

fn main(
    prev: call_data(0) [Field; STATE_FIELDS],
    prev_vk: Vk,
) -> return_data [Field; STATE_FIELDS] {
    let h = check_vk(prev[S_VK_TREE_ROOT], ROLE_KERNEL_ENVELOPE, prev_vk);
    std::verify_proof_with_type(prev_vk.key, [], [], h, PROOF_TYPE_HN_TAIL);
    prev
}
