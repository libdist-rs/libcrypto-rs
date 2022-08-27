use std::fmt;
use asn1_der::{DerObject, Sink, Asn1DerError, typed::{DerTypeView, DerEncodable, DerDecodable, Sequence}, Asn1DerErrorVariant, VecBacking};
use ring::signature::{self, RSA_PKCS1_2048_8192_SHA256};

use crate::DecodingError;

/// An RSA public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub(crate) Vec<u8>);

impl PublicKey {
    /// Verify an RSA signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let key = signature::UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.0);
        key.verify(msg, sig).is_ok()
    }

    /// Encode the RSA public key in DER as a PKCS#1 RSAPublicKey structure,
    /// as defined in [RFC3447].
    ///
    /// [RFC3447]: https://tools.ietf.org/html/rfc3447#appendix-A.1.1
    pub fn encode_pkcs1(&self) -> Vec<u8> {
        // This is the encoding currently used in-memory, so it is trivial.
        self.0.clone()
    }

    /// Encode the RSA public key in DER as a X.509 SubjectPublicKeyInfo structure,
    /// as defined in [RFC5280].
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280#section-4.1
    pub fn encode_x509(&self) -> Vec<u8> {
        let spki = Asn1SubjectPublicKeyInfo {
            algorithmIdentifier: Asn1RsaEncryption {
                algorithm: Asn1OidRsaEncryption,
                parameters: ()
            },
            subjectPublicKey: Asn1SubjectPublicKey(self.clone())
        };
        let mut buf = Vec::new();
        let buf = spki.encode(&mut buf).map(|_| buf)
            .expect("RSA X.509 public key encoding failed.");
        buf
    }

    /// Decode an RSA public key from a DER-encoded X.509 SubjectPublicKeyInfo
    /// structure. See also `encode_x509`.
    pub fn decode_x509(pk: &[u8]) -> Result<PublicKey, DecodingError> {
        Asn1SubjectPublicKeyInfo::decode(pk)
            .map_err(|e| DecodingError::new("RSA X.509").source(e))
            .map(|spki| spki.subjectPublicKey.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(PKCS1): ")?;
        for byte in &self.0 {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

//////////////////////////////////////////////////////////////////////////////
// DER encoding / decoding of public keys
//
// Primer: http://luca.ntop.org/Teaching/Appunti/asn1.html
// Playground: https://lapo.it/asn1js/

/// A raw ASN1 OID.
#[derive(Copy, Clone)]
struct Asn1RawOid<'a> {
    object: DerObject<'a>
}

impl<'a> Asn1RawOid<'a> {
    /// The underlying OID as byte literal.
    pub fn oid(&self) -> &[u8] {
        self.object.value()
    }

    /// Writes an OID raw `value` as DER-object to `sink`.
    pub fn write<S: Sink>(value: &[u8], sink: &mut S) -> Result<(), Asn1DerError> {
        DerObject::write(Self::TAG, value.len(), &mut value.iter(), sink)
    }
}

impl<'a> DerTypeView<'a> for Asn1RawOid<'a> {
    const TAG: u8 = 6;

    fn object(&self) -> DerObject<'a> {
        self.object
    }
}

impl<'a> DerEncodable for Asn1RawOid<'a> {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        self.object.encode(sink)
    }
}

impl<'a> DerDecodable<'a> for Asn1RawOid<'a> {
    fn load(object: DerObject<'a>) -> Result<Self, Asn1DerError> {
        if object.tag() != Self::TAG {
            return Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "DER object tag is not the object identifier tag.",
            )));
        }

        Ok(Self { object })
    }
}

/// The ASN.1 OID for "rsaEncryption".
#[derive(Clone)]
struct Asn1OidRsaEncryption;

impl Asn1OidRsaEncryption {
    /// The DER encoding of the object identifier (OID) 'rsaEncryption' for
    /// RSA public keys defined for X.509 in [RFC-3279] and used in
    /// SubjectPublicKeyInfo structures defined in [RFC-5280].
    ///
    /// [RFC-3279]: https://tools.ietf.org/html/rfc3279#section-2.3.1
    /// [RFC-5280]: https://tools.ietf.org/html/rfc5280#section-4.1
    const OID: [u8;9] = [ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 ];
}

impl DerEncodable for Asn1OidRsaEncryption {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        Asn1RawOid::write(&Self::OID, sink)
    }
}

impl DerDecodable<'_> for Asn1OidRsaEncryption {
    fn load(object: DerObject<'_>) -> Result<Self, Asn1DerError> {
        match Asn1RawOid::load(object)?.oid() {
            oid if oid == Self::OID => Ok(Self),
            _ => Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData(
                "DER object is not the 'rsaEncryption' identifier.",
            )))
        }
    }
}

/// The ASN.1 AlgorithmIdentifier for "rsaEncryption".
struct Asn1RsaEncryption {
    algorithm: Asn1OidRsaEncryption,
    parameters: ()
}

impl DerEncodable for Asn1RsaEncryption {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        let mut algorithm_buf = Vec::new();
        let algorithm = self.algorithm.der_object(VecBacking(&mut algorithm_buf))?;

        let mut parameters_buf = Vec::new();
        let parameters = self.parameters.der_object(VecBacking(&mut parameters_buf))?;

        Sequence::write(&[algorithm, parameters], sink)
    }
}

impl DerDecodable<'_> for Asn1RsaEncryption {
    fn load(object: DerObject<'_>) -> Result<Self, Asn1DerError> {
        let seq: Sequence = Sequence::load(object)?;

        Ok(Self{
            algorithm: seq.get_as(0)?,
            parameters: seq.get_as(1)?,
        })
    }
}

/// The ASN.1 SubjectPublicKey inside a SubjectPublicKeyInfo,
/// i.e. encoded as a DER BIT STRING.
struct Asn1SubjectPublicKey(PublicKey);

impl DerEncodable for Asn1SubjectPublicKey {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        let pk_der = &(self.0).0;
        let mut bit_string = Vec::with_capacity(pk_der.len() + 1);
        // The number of bits in pk_der is trivially always a multiple of 8,
        // so there are always 0 "unused bits" signaled by the first byte.
        bit_string.push(0u8);
        bit_string.extend(pk_der);
        DerObject::write(3, bit_string.len(), &mut bit_string.iter(), sink)?;
        Ok(())
    }
}

impl DerDecodable<'_> for Asn1SubjectPublicKey {
    fn load(object: DerObject<'_>) -> Result<Self, Asn1DerError> {
        if object.tag() != 3 {
            return Err(Asn1DerError::new(
                Asn1DerErrorVariant::InvalidData("DER object tag is not the bit string tag."),
            ));
        }

        let pk_der: Vec<u8> = object.value().into_iter().skip(1).cloned().collect();
        // We don't parse pk_der further as an ASN.1 RsaPublicKey, since
        // we only need the DER encoding for `verify`.
        Ok(Self(PublicKey(pk_der)))
    }
}

/// ASN.1 SubjectPublicKeyInfo
#[allow(non_snake_case)]
struct Asn1SubjectPublicKeyInfo {
    algorithmIdentifier: Asn1RsaEncryption,
    subjectPublicKey: Asn1SubjectPublicKey
}

impl DerEncodable for Asn1SubjectPublicKeyInfo {
    fn encode<S: Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        let mut identifier_buf = Vec::new();
        let identifier = self.algorithmIdentifier.der_object(VecBacking(&mut identifier_buf))?;

        let mut key_buf = Vec::new();
        let key = self.subjectPublicKey.der_object(VecBacking(&mut key_buf))?;

        Sequence::write(&[identifier, key], sink)
    }
}

impl DerDecodable<'_> for Asn1SubjectPublicKeyInfo {
    fn load(object: DerObject<'_>) -> Result<Self, Asn1DerError> {
        let seq: Sequence = Sequence::load(object)?;

        Ok(Self {
            algorithmIdentifier: seq.get_as(0)?,
            subjectPublicKey: seq.get_as(1)?,
        })
    }
}

