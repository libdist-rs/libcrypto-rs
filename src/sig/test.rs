#[cfg(test)]
mod test {
    use std::error::Error;
    use crate::{Algorithm, NetworkObject, PrivateKey};

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
}
