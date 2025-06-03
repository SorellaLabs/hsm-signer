use alloy_consensus::{SignableTransaction, TxLegacy};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, ObjectClass},
    session::UserType,
    types::AuthPin,
};
use sha3::{Digest, Keccak256};
use std::{env, path::Path, time::Instant};

const PKCS11_LIB: &str = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so";
const KEY_LABEL: &str = "angstrom_test-eth-private-key";

fn main() -> eyre::Result<()> {
    // ── 1.  Load & initialise the PKCS #11 library
    let pkcs11 = Pkcs11::new(Path::new(PKCS11_LIB))?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // ── 2.  Pick the first slot that has a token present
    let slot = pkcs11.get_slots_with_token()?[0];

    // ── 3.  Open an RW session and log in
    let sess = pkcs11.open_rw_session(slot)?;

    // PIN format: <username>:<password>  (e.g., "CryptoUser:CUPassword123!")
    let pin = env::var("CLOUDHSM_PIN").expect("export CLOUDHSM_PIN=\"CryptoUser:YourPass\"");
    sess.login(UserType::User, Some(&AuthPin::new(pin)))?;

    // ── 4.  Locate the secp256k1 private key by label
    let tmpl = vec![
        // Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(KEY_LABEL.into()),
    ];
    let handles = sess.find_objects(&tmpl)?;
    let key = handles
        .get(0)
        .copied()
        .expect("key with that label not found");

    // ── 5.  Hash your message with Keccak-256
    let msg = TxLegacy::default();
    let digest = msg.signature_hash().0;

    // ── 6.  Sign – PKCS #11 expects the raw hash for CKM_ECDSA

    let sig = with_time("sign tx", || sess.sign(&Mechanism::Ecdsa, key, &digest))?;

    // signature = r||s (64 bytes for secp256k1)
    println!("Keccak-256(d) : 0x{}", hex::encode(digest));
    println!("Raw r||s sig  : 0x{}", hex::encode(&sig));

    // ── 7.  Clean up
    sess.logout()?;
    pkcs11.finalize();
    Ok(())
}

fn with_time<F: Fn() -> T, T>(name: &str, f: F) -> T {
    let now = Instant::now();
    let out = f();
    println!(
        "{name}: {} mcs - {} ms",
        now.elapsed().as_micros(),
        now.elapsed().as_millis()
    );
    out
}
