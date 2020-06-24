use prost::Message;
use secp256k1::{recover, sign, verify, Message as SecpMessage, PublicKey, RecoveryId, SecretKey, Signature};
use sha2::{Digest, Sha256};

mod p2p_messages {
    include!(concat!(env!("OUT_DIR"), "/mm2_libp2p.pb.rs"));
}

use p2p_messages::ForTest;

/// SignedMessage, should contain signature with recovery id.
/// Fields should not ever become public, the payload only should be accessed if signature is valid
#[derive(PartialEq, ::prost::Message)]
pub struct SignedMessage {
    #[prost(bytes, tag="1")]
    signature: std::vec::Vec<u8>,
    #[prost(bytes, tag="2")]
    payload: std::vec::Vec<u8>,
}

impl SignedMessage {
    /// Attempts to decode the payload and also returns recovered pubkey and signature.
    /// Consumes self, the message should not be reused if signature check failed.
    pub fn parse_payload<T: Default + Message>(self) -> Result<(PublicKey, Signature, T), ()> {
        if self.signature.len() != 65 { return Err(()); }

        let sig = Signature::parse_slice(&self.signature[..64]).map_err(|_| ())?;
        let rec_id = RecoveryId::parse(self.signature[64]).map_err(|_| ())?;

        // create a Sha256 object
        let mut hasher = Sha256::new();

        // write input message
        hasher.update(&self.payload);

        // read hash digest and consume hasher
        let result = hasher.finalize();
        let sig_hash = SecpMessage::parse(&result.into());

        let pubkey = recover(&sig_hash, &sig, &rec_id).map_err(|_| ())?;
        if !verify(&sig_hash, &sig, &pubkey) { return Err(()); }

        let payload = T::decode(self.payload.as_slice()).map_err(|_| ())?;
        Ok((pubkey, sig, payload))
    }
}

#[test]
fn test_signed_message_de_encode() {
    let secret = SecretKey::random(&mut rand::thread_rng());
    let initial_msg = ForTest {
        payload: vec![0; 32]
    };

    let mut encoded_msg = Vec::with_capacity(initial_msg.encoded_len());

    initial_msg.encode(&mut encoded_msg)
        .expect("Buffer has sufficient capacity");

    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(&encoded_msg);

    // read hash digest and consume hasher
    let result = hasher.finalize();
    let sig_hash = SecpMessage::parse(&result.into());
    let (sig, rec_id) = sign(&sig_hash, &secret);
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(&sig.serialize());
    signature.push(rec_id.into());
    let msg = SignedMessage {
        signature,
        payload: encoded_msg,
    };

    let parsed = msg.parse_payload::<ForTest>().unwrap();
    assert_eq!(parsed.1, sig);
    assert_eq!(parsed.2, initial_msg);
}
