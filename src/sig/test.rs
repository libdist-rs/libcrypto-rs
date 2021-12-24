#[cfg(test)]
mod test {
    use std::error::Error;
    use crate::{Algorithm, NetworkObject, PrivateKey, PublicKey};

    #[derive(Debug)]
    struct Data (Vec<u8>);
    impl NetworkObject for Data {
        type Object = Data;

        fn to_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn from_bytes(data: &[u8]) -> <Self as NetworkObject>::Object {
            Self{ 0: data.to_vec() }
        }
    }

    fn test_keypair(key: PrivateKey) -> Result<(), Box<dyn Error>> {
        let data = Data{ 0: vec![1; 1024*1024]};
        let sig = key.sign(&data).map_err(|e| e.to_string())?;

        let pub_key = key.public()?;
        let res = pub_key.verify(&data, &sig).map_err(|e| e.to_string())?;
        Ok(res)
    }

    fn test_codec(key: PrivateKey) -> Result<(), Box<dyn Error>> {
        let pub_key = key.public()?;
        let serialized = bincode::serialize(&pub_key)?;
        let new_pub_key: PublicKey = bincode::deserialize(serialized.as_ref())?;
        if new_pub_key != pub_key {
            return Err(format!("{}", "The two public keys are not equal").into());
        }

        let serialized = bincode::serialize(&key)?;
        let new_key: PrivateKey = bincode::deserialize(&serialized)?;
        let serialized2 = bincode::serialize(&new_key)?;
        if serialized2 != serialized {
            return Err(format!("{}", "The two private keys are not equal").into());
        }
        Ok(())
    }

    #[test]
    fn test_rsa() -> Result<(), Box<dyn Error>> {
        let alg = Algorithm::RSA;
        let key_pair = alg.generate()?;
        test_keypair(key_pair)
    }

    #[test]
    fn test_ed25519() -> Result<(), Box<dyn Error>> {
        let alg = Algorithm::ED25519;
        let key_pair = alg.generate()?;

        test_keypair(key_pair)
    }

    #[test]
    fn test_secp256k1() -> Result<(), Box<dyn Error>> {
        let alg = Algorithm::SECP256K1;
        let key_pair = alg.generate()?;

        test_keypair(key_pair)
    }

    #[test]
    fn test_all() -> Result<(), Box<dyn Error>> {
        for algo in Algorithm::VALUES {
            test_keypair(algo.generate()?)?;
        }
        Ok(())
    }

    #[test]
    fn test_all_codec() -> Result<(), Box<dyn Error>> {
        for algo in Algorithm::VALUES {
            test_codec(algo.generate()?)?;
        }
        Ok(())
    }
}
