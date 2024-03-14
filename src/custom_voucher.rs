use minerva_voucher::Voucher;
pub use minerva_voucher::{VoucherError, Sign, Validate, SignatureAlgorithm, attr::*};
use super::utils;
use std::convert::TryFrom;

pub struct CustomVoucher(Voucher);

impl core::ops::Deref for CustomVoucher {
    type Target = Voucher;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::ops::DerefMut for CustomVoucher {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl TryFrom<&[u8]> for CustomVoucher {
    type Error = VoucherError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(Voucher::try_from(raw)?))
    }
}

impl CustomVoucher {
    pub fn new_vrq() -> Self { Self(Voucher::new_vrq()) }
    pub fn set(&mut self, attr: Attr) -> &mut Self {
        self.0.set(attr);
        self
    }
}

//

type CustomError = mbedtls::Error;
const ERROR_ASN1_FAILED: i32 = -1;

use mbedtls::pk::{EcGroup, EcGroupId, Pk, ECDSA_MAX_LEN};
use mbedtls::ecp::EcPoint;
use mbedtls::x509::certificate::Certificate;
use mbedtls::hash as mbedtls_hash;

impl Sign for CustomVoucher {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) -> Result<&mut Self, VoucherError> {
        if let Err(_) = sign_with_rust_mbedtls(privkey_pem, alg, self.to_sign(alg)) {
            Err(VoucherError::SigningFailed)
        } else {
            Ok(self)
        }
    }
}

fn sign_with_rust_mbedtls(
    mut rng: mbedtls::rng::OsEntropy,
    privkey_pem: &[u8],
    alg: SignatureAlgorithm,
    (sig_out, sig_struct): (&mut Vec<u8>, &[u8])
) -> Result<(), CustomError> {
    let (ref hash, md_ty) = compute_digest(sig_struct, &alg)?;
    let mut sig = vec![0u8; ECDSA_MAX_LEN];
    let sig_len = Pk::from_private_key(&utils::null_terminate_bytes!(privkey_pem), None)?
        .sign_deterministic(md_ty, &hash, &mut sig, &mut rng)?;
    sig.truncate(sig_len);

    *sig_out = sig;

    Ok(())
}

//

impl Validate for CustomVoucher {
    fn validate(&self, pem: Option<&[u8]>) -> Result<&Self, VoucherError> {
        match validate_with_rust_mbedtls(pem, self.to_validate()) {
            Ok(true) => Ok(self),
            Ok(false) => Err(VoucherError::ValidationFailed),
            Err(_) => Err(VoucherError::ValidationFailed),
        }
    }
}

fn validate_with_rust_mbedtls(
    pem: Option<&[u8]>,
    (signer_cert, sig_alg, msg): (Option<&[u8]>, Option<(&[u8], &SignatureAlgorithm)>, &[u8])
) -> Result<bool, CustomError> {
    if sig_alg.is_none() { return Ok(false); }
    let (signature, alg) = sig_alg.unwrap();

    let ref signature = if utils::is_asn1_signature(signature) {
        signature.to_vec()
    } else {
        utils::asn1_signature_from(signature).or(Err(CustomError::Other(ERROR_ASN1_FAILED)))?
    };

    let (ref hash, md_ty) = compute_digest(msg, alg)?;

    if let Some(pem) = pem {
        let pem = &utils::null_terminate_bytes!(pem);

        if let Ok(mut pk) = Pk::from_private_key(pem, None) {
            return pk.verify(md_ty, hash, signature).and(Ok(true));
        }

        Certificate::from_pem(pem)?
            .public_key_mut()
            .verify(md_ty, hash, signature)
            .and(Ok(true))
    } else if let Some(cert) = signer_cert {
        let grp = EcGroup::new(EcGroupId::SecP256R1)?;

        let prefix = *cert.get(0).unwrap();
        if prefix == 0x02 || prefix == 0x03 {
            // "Compressed point, which mbedtls does not understand"
            // according to 'src/ecp/mod.rs' of the `rust-mbedtls` crate
            println!("validate(): warning: `cert` cannot be processed by vanilla mbedtls");
        }
        let pt = EcPoint::from_binary(&grp, cert)?;

        Pk::public_from_ec_components(grp.clone(), pt)?
            .verify(md_ty, hash, signature)
            .and(Ok(true))
    } else {
        println!("validate(): Neither external masa cert nor signer cert is available.");
        Ok(false)
    }
}

//

fn compute_digest(msg: &[u8], alg: &SignatureAlgorithm) -> Result<(Vec<u8>, mbedtls_hash::Type), CustomError> {
    let (md_type, digest_len) = match *alg {
        SignatureAlgorithm::ES256 => (mbedtls_hash::Type::Sha256, 32),
        SignatureAlgorithm::ES384 => (mbedtls_hash::Type::Sha384, 48),
        SignatureAlgorithm::ES512 => (mbedtls_hash::Type::Sha512, 64),
        SignatureAlgorithm::PS256 => unimplemented!("handle PS256"),
    };

    let mut digest = vec![0u8; digest_len];
    mbedtls_hash::Md::hash(md_type, msg, &mut digest)?;

    Ok((digest, md_type))
}
