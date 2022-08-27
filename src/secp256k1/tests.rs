use super::*;

#[test]
fn secp256k1_secret_from_bytes() {
    let sk1 = SecretKey::generate();
    let mut sk_bytes = [0; 32];
    sk_bytes.copy_from_slice(&sk1.0.serialize()[..]);
    let sk2 = SecretKey::from_bytes(&mut sk_bytes).unwrap();
    assert_eq!(sk1.0.serialize(), sk2.0.serialize());
    assert_eq!(sk_bytes, [0; 32]);
}
