//! BOLT 8's published test vectors (Appendix A): the three acts, the keys after the handshake,
//! and the transport messages 0, 1, 500, 501, 1000 and 1001 (across two key rotations).

use secp256k1::{PublicKey, SecretKey};
use xbt_hashlink::noise::{Handshake, ACT_ONE, ACT_THREE, ACT_TWO};

fn sk(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn bolt8_handshake_and_transport() {
    let rs = PublicKey::from_secret_key(secp256k1::SECP256K1, &sk(0x21));
    assert_eq!(hex::encode(rs.serialize()), "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
    let mut init = Handshake::initiator(b"lightning", sk(0x11), sk(0x12), rs);
    let mut resp = Handshake::responder(b"lightning", sk(0x21), sk(0x22));

    let one = init.act_one();
    assert_eq!(one.to_vec(), h("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"));
    resp.read_act_one(&one).unwrap();
    let two = resp.act_two();
    assert_eq!(two.to_vec(), h("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"));
    init.read_act_two(&two).unwrap();
    let (three, mut ti) = init.act_three();
    assert_eq!(three.to_vec(), h("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"));
    let mut tr = resp.read_act_three(&three).unwrap();

    assert_eq!(ti.send.key().to_vec(), h("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"));
    assert_eq!(ti.recv.key().to_vec(), h("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"));
    assert_eq!(ti.ck.to_vec(), h("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"));
    assert_eq!(tr.ck, ti.ck);
    assert_eq!(tr.send.key(), ti.recv.key());
    assert_eq!(tr.recv.key(), ti.send.key());
    assert_eq!(tr.remote, PublicKey::from_secret_key(secp256k1::SECP256K1, &sk(0x11)));

    let want = [
        (0, "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95"),
        (1, "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1"),
        (500, "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8"),
        (501, "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd"),
        (1000, "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09"),
        (1001, "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36"),
    ];
    for i in 0..1002 {
        let c = ti.send.encrypt(b"hello").unwrap();
        if let Some((_, w)) = want.iter().find(|(n, _)| *n == i) {
            assert_eq!(hex::encode(&c), *w, "message {i}");
        }
        let len: [u8; 18] = c[..18].try_into().unwrap();
        assert_eq!(tr.recv.decrypt_len(&len).unwrap(), 5);
        assert_eq!(tr.recv.decrypt_body(&c[18..]).unwrap(), b"hello");
    }
}

#[test]
fn act_sizes_and_tamper() {
    assert_eq!((ACT_ONE, ACT_TWO, ACT_THREE), (50, 50, 66));
    let rs = PublicKey::from_secret_key(secp256k1::SECP256K1, &sk(0x21));
    let mut init = Handshake::initiator(b"lightning", sk(0x11), sk(0x12), rs);
    let mut one = init.act_one();
    one[40] ^= 1;
    let mut resp = Handshake::responder(b"lightning", sk(0x21), sk(0x22));
    assert!(resp.read_act_one(&one).is_err());
    // a different prologue never completes
    let mut init = Handshake::initiator(xbt_hashlink::noise::PROLOGUE, sk(0x11), sk(0x12), rs);
    let mut resp = Handshake::responder(b"lightning", sk(0x21), sk(0x22));
    assert!(resp.read_act_one(&init.act_one()).is_err());
}
