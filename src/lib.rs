use std::path::Path;

use alloy_primitives::{Address, B256, ChainId};
use alloy_signer::{
    Signature, SignerSync,
    k256::ecdsa::{self, VerifyingKey},
};

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use once_cell::sync::OnceCell;

pub static PKCS11: OnceCell<Pkcs11> = OnceCell::new();

pub struct Pkcs11Signer {
    session: Session,
    address: Address,
    key_handle: ObjectHandle,
    chain_id: ChainId,
}

impl Pkcs11Signer {
    pub fn new_from_env(
        public_key_label: &str,
        private_key_label: &str,
        pkcs11_lib: &str,
        chain_id: ChainId,
    ) -> Result<Self, cryptoki::error::Error> {
        let pkcs11 = PKCS11.get_or_try_init(|| {
            let pkcs11 = Pkcs11::new(Path::new(pkcs11_lib))?;
            pkcs11.initialize(CInitializeArgs::OsThreads)?;
            Ok::<_, cryptoki::error::Error>(pkcs11)
        })?;

        let slot = pkcs11.get_slots_with_token()?[0];
        let session = pkcs11.open_rw_session(slot)?;

        let pin = std::env::var("CLOUDHSM_PIN")
            .expect("CLOUDHSM_PIN not found -- `export CLOUDHSM_PIN=\"CryptoUser:YourPass\"`");
        session.login(UserType::User, Some(&AuthPin::new(pin)))?;

        let pub_handles = session.find_objects(&[Attribute::Label(public_key_label.into())])?;
        let pub_key = pub_handles
            .get(0)
            .copied()
            .expect("key with that label not found");

        // session.k

        let ec_attr = session.get_attributes(pub_key, &[AttributeType::EcPoint])?;
        let der = match &ec_attr[0] {
            Attribute::EcPoint(point) => point.clone(),
            _ => panic!("Unexpected EC_POINT type"),
        };
        let address = if der.len() > 2 && der[0] == 0x04 {
            Address::from_slice(&der[2..])
        } else {
            Address::from_slice(&der[..])
        };

        let priv_handles = session.find_objects(&[Attribute::Label(private_key_label.into())])?;
        let priv_key = priv_handles
            .get(0)
            .copied()
            .expect("key with that label not found");

        Ok(Self {
            session,
            address,
            key_handle: priv_key,
            chain_id,
        })
    }

    pub fn sign_message<B: AsRef<[u8]>>(&self, msg: B) -> Result<Vec<u8>, cryptoki::error::Error> {
        self.session
            .sign(&Mechanism::Ecdsa, self.key_handle, msg.as_ref())
    }

    pub fn sign_digest_with_key(&self, digest: &B256) -> eyre::Result<ecdsa::Signature> {
        let raw = self.sign_message(digest)?;
        let sig = ecdsa::Signature::from_der(raw.as_ref())?;
        Ok(sig.normalize_s().unwrap_or(sig))
    }
}

// impl SignerSync for Pkcs11Signer {
//     fn sign_hash_sync(&self, hash: &B256) -> alloy_signer::Result<Signature> {
//         self.signer.sign_hash(hash)
//     }

//     fn chain_id_sync(&self) -> Option<ChainId> {
//         Some(self.chain_id)
//     }
// }

fn sig_from_digest_bytes_trial_recovery(
    sig: ecdsa::Signature,
    hash: &B256,
    pubkey: &VerifyingKey,
) -> Signature {
    let signature = Signature::from_signature_and_parity(sig, false);
    if check_candidate(&signature, hash, pubkey) {
        return signature;
    }

    let signature = signature.with_parity(true);
    if check_candidate(&signature, hash, pubkey) {
        return signature;
    }

    panic!("bad sig");
}
fn check_candidate(signature: &Signature, hash: &B256, pubkey: &VerifyingKey) -> bool {
    signature
        .recover_from_prehash(hash)
        .map(|key| key == *pubkey)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{SignableTransaction, TxLegacy};
    use alloy_primitives::{Address, TxKind};
    use alloy_signer_local::LocalSigner;

    use super::*;

    #[test]
    fn test_sign() {
        let signer = Pkcs11Signer::new_from_env(
            "angstrom_test-eth-public-key",
            "angstrom_test-eth-private-key",
            "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
            ChainId::from(1u64),
        )
        .unwrap();

        let mut first_msg = TxLegacy::default();
        first_msg.to = TxKind::Call(Address::random());

        let hash = first_msg.signature_hash();

        // LocalSigner::random().si

        let mut second_msg = TxLegacy::default();
        second_msg.to = TxKind::Call(Address::random());
    }
}
