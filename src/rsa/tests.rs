use std::error::Error;
use std::fmt;

use quickcheck::*;
use rand::seq::SliceRandom;
use ring::signature::KeyPair;

use super::*;
use crate::SigningError;

const KEY1: &'static [u8] = include_bytes!("test/rsa-2048.pk8");
const KEY2: &'static [u8] = include_bytes!("test/rsa-3072.pk8");
const KEY3: &'static [u8] = include_bytes!("test/rsa-4096.pk8");

#[derive(Clone)]
struct SomeKeypair(Keypair);

impl fmt::Debug for SomeKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "SomeKeypair") }
}

impl Arbitrary for SomeKeypair {
    fn arbitrary(generator: &mut Gen) -> SomeKeypair {
        let mut rng = rand::thread_rng();
        let mut key = [KEY1, KEY2, KEY3].choose(&mut rng).unwrap().to_vec();
        SomeKeypair(Keypair::from_pkcs8(&mut key).unwrap())
    }
}

#[test]
fn rsa_from_pkcs8() {
    assert!(Keypair::from_pkcs8(&mut KEY1.to_vec()).is_ok());
    assert!(Keypair::from_pkcs8(&mut KEY2.to_vec()).is_ok());
    assert!(Keypair::from_pkcs8(&mut KEY3.to_vec()).is_ok());
}

#[test]
fn rsa_x509_encode_decode() {
    fn prop(SomeKeypair(kp): SomeKeypair) -> Result<bool, String> {
        let pk = kp.public();
        PublicKey::decode_x509(&pk.encode_x509()).map_err(|e| e.to_string()).map(|pk2| pk2 == pk)
    }
    QuickCheck::new().tests(10).quickcheck(prop as fn(_) -> _);
}

#[test]
fn rsa_sign_verify() {
    fn prop(SomeKeypair(kp): SomeKeypair, msg: Vec<u8>) -> Result<bool, SigningError> {
        kp.secret().sign(&msg).map(|s| kp.public().verify(&msg, &s))
    }
    QuickCheck::new().tests(10).quickcheck(prop as fn(_, _) -> _);
}

#[test]
fn test_decode_encode() {
    fn prop() -> Result<bool, Box<dyn Error>> {
        let kp = Keypair::generate()?;
        let serialized = bincode::serialize(&kp)?;
        let new_kp: Keypair = bincode::deserialize(&serialized)?;
        Ok(new_kp.key.public_key().as_ref() == kp.key.public_key().as_ref())
    }
    QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
}
