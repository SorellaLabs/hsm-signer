use std::{path::Path, sync::Arc};

use alloy_consensus::SignableTransaction;
use alloy_primitives::{Address, B256, ChainId, keccak256};
use alloy_signer::{Signature, Signer, SignerSync, sign_transaction_with_chain_id};
use async_trait::async_trait;
use k256::{
    EncodedPoint,
    ecdsa::{self, VerifyingKey},
};

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use tracing::instrument;

pub static PKCS11: OnceCell<Pkcs11> = OnceCell::new();

#[derive(Clone)]
pub struct Pkcs11Signer {
    session: Arc<Mutex<Session>>,
    pk_handle: ObjectHandle,
    pubkey: VerifyingKey,
    address: Address,
    chain_id: Option<ChainId>,
}

impl std::fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("pubkey", &hex::encode(self.pubkey.to_sec1_bytes()))
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

// trait Pkcs11SignerSS: Send + Sync {}
// impl Pkcs11SignerSS for Pkcs11Signer {}

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
            _ => panic!("Expected EC_POINT type"),
        };
        let address = address_from_ec_point(&der).unwrap();
        let pubkey = verifying_key_ec_point(&der).unwrap();

        let priv_handles = session.find_objects(&[Attribute::Label(private_key_label.into())])?;
        let priv_key = priv_handles
            .get(0)
            .copied()
            .expect("key with that label not found");

        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            address,
            pk_handle: priv_key,
            chain_id: Some(chain_id),
            pubkey,
        })
    }

    pub fn sign_message<B: AsRef<[u8]>>(&self, msg: B) -> Result<Vec<u8>, cryptoki::error::Error> {
        let lock = self.session.lock();
        let out = lock
            .sign(&Mechanism::EcdsaSha256, self.pk_handle, msg.as_ref())
            .unwrap();
        drop(lock);
        Ok(out)
    }

    pub fn sign_digest_with_key(&self, digest: &B256) -> eyre::Result<ecdsa::Signature> {
        let raw = self.sign_message(digest)?;
        println!("{raw:?}");
        let sig = ecdsa::Signature::from_slice(&raw).unwrap();
        Ok(sig.normalize_s().unwrap_or(sig))
    }

    pub fn sign_digest(&self, digest: &B256) -> eyre::Result<ecdsa::Signature> {
        self.sign_digest_with_key(digest)
    }

    pub fn sign_digest_inner(&self, digest: &B256) -> eyre::Result<Signature> {
        let sig = self.sign_digest(digest).unwrap();
        Ok(sig_from_digest_bytes_trial_recovery(
            sig,
            digest,
            &self.pubkey,
        ))
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl alloy_network::TxSigner<Signature> for Pkcs11Signer {
    fn address(&self) -> Address {
        self.address
    }

    #[inline]
    #[doc(alias = "sign_tx")]
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> alloy_signer::Result<Signature> {
        sign_transaction_with_chain_id!(self, tx, self.sign_hash(&tx.signature_hash()).await)
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl Signer for Pkcs11Signer {
    #[instrument(err)]
    #[allow(clippy::blocks_in_conditions)]
    async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<Signature> {
        self.sign_digest_inner(hash)
            .map_err(alloy_signer::Error::other)
    }

    #[inline]
    fn address(&self) -> Address {
        self.address
    }

    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    #[inline]
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

impl SignerSync for Pkcs11Signer {
    #[inline]
    fn sign_hash_sync(&self, hash: &B256) -> alloy_signer::Result<Signature> {
        self.sign_digest_inner(hash)
            .map_err(alloy_signer::Error::other)
    }

    #[inline]
    fn chain_id_sync(&self) -> Option<ChainId> {
        self.chain_id
    }
}

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

fn address_from_ec_point(der: &[u8]) -> eyre::Result<Address> {
    // 1.  DER-encoded OCTET STRING => skip the tag & length
    let (_, octet) = der.split_at(2);

    // 2.  First byte of the OCTET STRING is 0x04 (uncompressed prefix)
    if octet.len() != 65 || octet[0] != 0x04 {
        eyre::bail!("unexpected EC point format");
    }
    let pubkey = &octet[1..]; // 64-byte X‖Y

    // 3.  Keccak-256 and 4. take the last 20 bytes
    let hash = keccak256(pubkey);
    Ok(Address::from_slice(&hash[12..]))
}

fn verifying_key_ec_point(der: &[u8]) -> eyre::Result<VerifyingKey> {
    // --- unwrap DER if present ---
    let sec1 = match der {
        [0x04, l, rest @ ..] if *l as usize == rest.len() => rest,
        _ => der,
    };

    // --- ensure 65-byte uncompressed point ---
    let sec1 = if sec1[0] == 0x04 && sec1.len() == 65 {
        sec1.to_vec()
    } else if sec1.len() == 64 {
        let mut buf = [0u8; 65];
        buf[0] = 0x04;
        buf[1..].copy_from_slice(sec1);
        buf.to_vec()
    } else {
        eyre::bail!("unexpected EC point format/length");
    };

    let point = EncodedPoint::from_bytes(sec1)?;
    Ok(VerifyingKey::from_encoded_point(&point)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy::signers::aws::AwsSigner;
    use alloy_consensus::{SignableTransaction, TxLegacy};
    use alloy_network::TxSigner;
    use alloy_primitives::{Address, TxKind};
    use alloy_signer::Signer;
    use aws_config::{BehaviorVersion, Region};

    #[tokio::test]
    async fn test_kms_equals() {
        dotenv::dotenv().ok();

        let hms_signer = Pkcs11Signer::new_from_env(
            "angstrom3-eth-public-key-test-meow",
            "angstrom3-eth-private-key-test-meow",
            "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
            ChainId::from(1u64),
        )
        .unwrap();

        let mut cfg_builder = aws_config::load_defaults(BehaviorVersion::latest())
            .await
            .into_builder();
        cfg_builder.set_region(Some(Region::from_static("ap-northeast-1")));
        let cfg = cfg_builder.build();

        let client = aws_sdk_kms::Client::new(&cfg);

        let key_id = "534a7042-d225-4a8a-8494-3fb29c9c1617";
        let kms_signer = AwsSigner::new(client, key_id.into(), Some(1))
            .await
            .unwrap();

        assert_eq!(
            hms_signer.address,
            alloy_signer::Signer::address(&kms_signer)
        );
        assert_eq!(hms_signer.pubkey, kms_signer.get_pubkey().await.unwrap());

        let mut tx = TxLegacy::default();
        tx.to = TxKind::Call(Address::random());

        let hsm_tx_sig0 = hms_signer.sign_transaction(&mut tx.clone()).await.unwrap();
        let kms_tx_sig0 = kms_signer.sign_transaction(&mut tx.clone()).await.unwrap();
        assert_eq!(hsm_tx_sig0, kms_tx_sig0);

        let hsm_tx_sig1 = hms_signer.sign_hash_sync(&tx.signature_hash()).unwrap();
        let kms_tx_sig1 = kms_signer.sign_hash(&tx.signature_hash()).await.unwrap();
        assert_eq!(hsm_tx_sig1, kms_tx_sig1);
    }
}
