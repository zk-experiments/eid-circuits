//! First kernel: folds the DSC step (the first proof of the IVC, OINK) and
//! starts the state from its outputs `[registry root, c_A]`.

use eid_kernel::{
    check_vk, PROOF_TYPE_OINK, ROLE_DSC, S_LINK, S_REGISTRY_ROOT, S_VK_TREE_ROOT, STATE_FIELDS, Vk,
};

fn main(
    step: call_data(1) [Field; 2],
    step_vk: Vk,
    vk_tree_root: Field,
) -> return_data [Field; STATE_FIELDS] {
    let h = check_vk(vk_tree_root, ROLE_DSC, step_vk);
    std::verify_proof_with_type(step_vk.key, [], [], h, PROOF_TYPE_OINK);
    let mut s: [Field; STATE_FIELDS] = [0; STATE_FIELDS];
    s[S_REGISTRY_ROOT] = step[0];
    s[S_VK_TREE_ROOT] = vk_tree_root;
    s[S_LINK] = step[1];
    s
}
