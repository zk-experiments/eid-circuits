//! Hiding kernel: folds the tail kernel (Chonk's final, zero-knowledge step)
//! and makes the statement public. Every document produces a proof under
//! this kernel's verification key, whatever step variants it used.

use eid_kernel::{
    check_vk, PROOF_TYPE_HN_FINAL, public_outputs, PublicOutputs, ROLE_KERNEL_TAIL, S_VK_TREE_ROOT,
    STATE_FIELDS, Vk,
};

fn main(prev: call_data(0) [Field; STATE_FIELDS], prev_vk: Vk) -> pub PublicOutputs {
    let h = check_vk(prev[S_VK_TREE_ROOT], ROLE_KERNEL_TAIL, prev_vk);
    std::verify_proof_with_type(prev_vk.key, [], [], h, PROOF_TYPE_HN_FINAL);
    public_outputs(prev)
}
