use super::*;

#[test]
fn secp256k1_secret_from_bytes() {
    let sk1 = SecretKey::generate();
    let mut sk_bytes = [0; 32];
    sk_bytes.copy_from_slice(&sk1.0.serialize()[..]);
    let sk2 = SecretKey::from_bytes(&mut sk_bytes).unwrap();
    assert_eq!(sk1.0.serialize(), sk2.0.serialize());
}

#[test]
fn test_codec() {
    let kpair = Keypair::generate();
    let mut bytes = kpair.to_bytes();
    let new_kpair = Keypair::from_bytes(&mut bytes);
    assert!(new_kpair.is_ok());
    let new_kpair = new_kpair.unwrap();
    assert!(kpair.public() == new_kpair.public());
}