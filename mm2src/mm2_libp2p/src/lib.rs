use prost::Message;
use secp256k1::{recover, sign, verify, Message as SecpMessage, PublicKey, RecoveryId, SecretKey, Signature};
use sha2::{Digest, Sha256};

pub mod p2p_messages {
    include!("mm2_libp2p.pb.rs");
}

fn sha256(input: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::new().chain(input).finalize().into()
}

use p2p_messages::{ForTest, MakerOrder};
use rand::RngCore;
use crate::p2p_messages::MakerOrderKeepAlive;

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
    pub fn create_and_sign<T: Message>(payload: &T, secret: &[u8; 32]) -> Result<Self, ()> {
        let secret = SecretKey::parse(secret).unwrap();
        let mut encoded_msg = Vec::with_capacity(payload.encoded_len());
        payload.encode(&mut encoded_msg).map_err(|_| ())?;
        let result = sha256(&encoded_msg);
        let sig_hash = SecpMessage::parse(&result.into());
        let (sig, rec_id) = sign(&sig_hash, &secret);
        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(&sig.serialize());
        signature.push(rec_id.into());
        Ok(SignedMessage {
            signature,
            payload: encoded_msg,
        })
    }

    /// Attempts to decode the payload and also returns recovered pubkey and signature.
    /// Consumes self, the message should not be reused if signature check failed.
    pub fn parse_payload<T: Default + Message>(self) -> Result<(PublicKey, Signature, T), ()> {
        if self.signature.len() != 65 { return Err(()); }

        let sig = Signature::parse_slice(&self.signature[..64])
            .expect("Input slice should always be 64 bytes long");
        let rec_id = RecoveryId::parse(self.signature[64]).map_err(|_| ())?;

        let sig_hash = sha256(&self.payload);
        let secp_message = SecpMessage::parse(&sig_hash);

        let pubkey = recover(&secp_message, &sig, &rec_id).map_err(|_| ())?;
        if !verify(&secp_message, &sig, &pubkey) { return Err(()); }

        let payload = T::decode(self.payload.as_slice()).map_err(|_| ())?;
        Ok((pubkey, sig, payload))
    }

    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut encoded_msg = Vec::with_capacity(self.encoded_len());
        self.encode(&mut encoded_msg).unwrap();
        encoded_msg
    }

    pub fn decode_from_slice(input: &[u8]) -> Result<Self, ()> {
        Message::decode(input).map_err(|_| ())
    }
}

#[test]
fn test_signed_message_de_encode() {
    let mut rng = rand::thread_rng();
    let secret = SecretKey::random(&mut rng);
    let initial_msg = ForTest {
        payload: vec![0; 32]
    };

    let signed = SignedMessage::create_and_sign(&initial_msg, &secret.serialize()).unwrap();
    let parsed = signed.parse_payload::<ForTest>().unwrap();
    assert_eq!(parsed.2, initial_msg);
    let mut uuid = [0u8; 16];
    rng.fill_bytes(&mut uuid);

    let order = MakerOrder {
        uuid: uuid.to_vec(),
        base_ticker: "KMD".to_string(),
        rel_ticker: "BTC".to_string(),
        price_numer: vec![3],
        price_denom: vec![1],
        max_volume_numer: vec![1],
        max_volume_denom: vec![2],
        min_volume_numer: vec![1],
        min_volume_denom: vec![777],
        base_confs: 5,
        rel_confs: 2,
        base_nota: false,
        rel_nota: true,
    };

    let signed = SignedMessage::create_and_sign(&order, &secret.serialize()).unwrap();
    println!("Signed maker order len {}", signed.encode_to_vec().len());

    let keep_alive = MakerOrderKeepAlive {
        uuid: uuid.to_vec(),
    };
    let signed = SignedMessage::create_and_sign(&keep_alive, &secret.serialize()).unwrap();
    println!("Signed maker order keep alive {}", signed.encode_to_vec().len());
}

#[test]
fn test_encoded_message_misses_field() {
    let msg = MakerOrder {
        uuid: vec![],
        base_ticker: "BASE".to_string(),
        rel_ticker: "".to_string(),
        price_numer: vec![],
        price_denom: vec![],
        max_volume_numer: vec![],
        max_volume_denom: vec![],
        min_volume_numer: vec![],
        min_volume_denom: vec![],
        base_confs: 0,
        rel_confs: 0,
        base_nota: false,
        rel_nota: false,
    };

    let mut encoded_msg = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut encoded_msg).unwrap();
    println!("{:?}", encoded_msg);
    println!("{}", hex::encode(encoded_msg));

    let encoded = vec![18, 4, 66, 65, 83, 69];
    let decoded = MakerOrder::decode(encoded.as_slice()).unwrap();
    println!("{:?}", decoded);

    println!("{:?}", bincode::serialize(&msg).unwrap());
}
