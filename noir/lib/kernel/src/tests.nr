use crate::{check_vk, ROLE_DSC, ROLE_SOD, Vk, VK_FIELDS, VK_TREE_HEIGHT};
use csca_registry::{hash, merkle_root, MerklePath};

fn tree_of_one(role: Field, key: [Field; VK_FIELDS]) -> (Field, Vk) {
    let path = MerklePath { index: 5, siblings: [7; VK_TREE_HEIGHT] };
    let root = merkle_root(hash([role, hash(key)]), path);
    (root, Vk { key, path })
}

#[test]
fn accepts_a_key_under_its_role() {
    let (root, vk) = tree_of_one(ROLE_DSC, [3; VK_FIELDS]);
    assert_eq(check_vk(root, ROLE_DSC, vk), hash([3; VK_FIELDS]));
}

#[test(should_fail_with = "verification key is not in the key tree under its role")]
fn rejects_a_key_under_another_role() {
    let (root, vk) = tree_of_one(ROLE_DSC, [3; VK_FIELDS]);
    let _ = check_vk(root, ROLE_SOD, vk);
}

#[test(should_fail_with = "verification key is not in the key tree under its role")]
fn rejects_another_key() {
    let (root, mut vk) = tree_of_one(ROLE_DSC, [3; VK_FIELDS]);
    vk.key[0] = 4;
    let _ = check_vk(root, ROLE_DSC, vk);
}
