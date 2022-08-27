use std::error::Error;
use crate::ed25519::Keypair;
use quickcheck::*;

fn eq_keypairs(kp1: &Keypair, kp2: &Keypair) -> bool {
    kp1.public() == kp2.public() &&
        kp1.secret().sk.as_bytes() == kp2.secret().sk.as_bytes()
}

#[test]
fn ed25519_keypair_encode_decode() {
    fn prop() -> anyhow::Result<bool> {
        let kp1 = Keypair::generate()?;
        let mut kp1_enc = bincode::serialize(&kp1)?;
        let kp2 = bincode::deserialize(&kp1_enc)?;
        Ok(eq_keypairs(&kp1, &kp2))
    }
    QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
}

#[test]
fn ed25519_signature() -> Result<(), Box<dyn Error>> {
    let kp = Keypair::generate()?;
    let pk = kp.public();
    let sk = kp.secret();

    let msg = "hello world".as_bytes();
    let sig = sk.sign(msg)?;
    assert!(pk.verify(msg, &sig));

    let mut invalid_sig = sig.clone();
    invalid_sig[3..6].copy_from_slice(&[10, 23, 42]);
    assert!(!pk.verify(msg, &invalid_sig));

    let invalid_msg = "h3ll0 w0rld".as_bytes();
    assert!(!pk.verify(invalid_msg, &sig));
    Ok(())
}
