use ink_prelude::vec::Vec;
use pink_extension as pink;
use pink::chain_extension::{signing};
use rlp::RlpStream;
use ethereum_types::{H160, H256, U256, U64};
use sha3::{Keccak256, Digest};

pub type Address = H160;
type Bytes = Vec<u8>;
const LEGACY_TX_ID: u64 = 0;

fn keccak_hash(x: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(x);
    hasher.finalize().into()
}

/// A transaction used for RLP encoding, hashing and signing.
#[derive(Clone, Debug, PartialEq)]
pub struct Transaction {
    pub to: Option<Address>,
    pub nonce: U256,
    pub gas: U256,
    pub gas_price: U256,
    pub value: U256,
    pub data: Vec<u8>,
    pub transaction_type: Option<U64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedTransaction {
    pub message_hash: H256,
    pub v: u64,
    pub r: H256,
    pub s: H256,
    pub raw_transaction: Bytes,   
}

pub struct Signature {
    /// V component in electrum format with chain-id replay protection.
    pub v: u64,
    /// R component of the signature.
    pub r: H256,
    /// S component of the signature.
    pub s: H256,
}
    
impl Transaction {
    fn rlp_append_legacy(&self, stream: &mut RlpStream) {
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas);
        if let Some(to) = self.to {
            stream.append(&to);
        } else {
            stream.append(&"");
        }
        stream.append(&self.value);
        stream.append(&self.data);
    }

    fn rlp_append_signature(&self, stream: &mut RlpStream, signature: &Signature) {
        stream.append(&signature.v);
        stream.append(&U256::from_big_endian(signature.r.as_bytes()));
        stream.append(&U256::from_big_endian(signature.s.as_bytes()));
    }

    fn encode_legacy(&self, chain_id: u64, signature: Option<&Signature>) -> RlpStream {
        let mut stream = RlpStream::new();
        stream.begin_list(9);

        self.rlp_append_legacy(&mut stream);

        if let Some(signature) = signature {
            self.rlp_append_signature(&mut stream, signature);
        } else {
            stream.append(&chain_id);
            stream.append(&0u8);
            stream.append(&0u8);
        }

        stream
    }

    fn encode(&self, chain_id: u64, signature: Option<&Signature>) -> Vec<u8> {
        match self.transaction_type.map(|t|t.as_u64()) {
            Some(LEGACY_TX_ID) | None => {
                let stream = self.encode_legacy(chain_id, signature);
                stream.out().to_vec()
            }
            _ => {
                panic!("Unsupported transaction type");
            }
        }
    }

    pub fn sign(self, privkey: &[u8;32], chain_id: Option<u64>) -> SignedTransaction {
        let encoded = self.encode(chain_id.unwrap(), None);
        let msg_hash = keccak_hash(&encoded);
        let sign = signing::ecdsa_sign_prehashed(privkey, msg_hash);

        let standard_v:u64 = sign[64].into();

        let v = if let Some(chain_id) = chain_id {
            // When signing with a chain ID, add chain replay protection.
            standard_v + 35 + chain_id * 2
        } else {
            // Otherwise, convert to 'Electrum' notation.
            standard_v + 27
        };
        let r = H256::from_slice(&sign[..32]);
        let s = H256::from_slice(&sign[32..64]);

        let signature =  Signature { v, r, s };
        let signed = self.encode(chain_id.unwrap(), Some(&signature));

        SignedTransaction {
            message_hash: msg_hash.into(),
            v: signature.v,
            r: signature.r,
            s: signature.s,
            raw_transaction: signed.into(),
        }

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn sign_transaction_data() {
        pink_extension_runtime::mock_ext::mock_all_ext();

        let tx = Transaction {
            nonce: 1.into(),
            gas: 21_000.into(),
            gas_price: 1_029_999_984.into(),
            to: Some(hex!("CB353EC62AB1A6CEFcC0e235C81f1610729579fA").into()),
            value: 1_000_000_000.into(),
            data: Vec::new(),
            transaction_type: None,
        };

        let skey = hex!("eb60f49350612f05fd520ff187353b6e883da0161bbc24aa2f4a008e7ea43609");
        let chain_id = 4;
        let signed = tx.sign(&skey, Some(chain_id));

        println!("signature: {:?}", signed);

        let expected = SignedTransaction {
            message_hash: hex!("6d44d42b1068d2cb345fae7ae8283984ce5d27f5e22220898c298c853898ebde").into(),
            v: 0x2C,
            r: hex!("5bfd43e1c4cd54681a367af85999174fb6cf32726ce73e699ff1f6ec4380cfb5").into(),
            s: hex!("108f79930f5cb6390b83685103b96c32d6a43af392d63ff925a96ef67b57e8de").into(),
            raw_transaction: hex!("f86701843d648d7082520894cb353ec62ab1a6cefcc0e235c81f1610729579fa843b9aca00802ca05bfd43e1c4cd54681a367af85999174fb6cf32726ce73e699ff1f6ec4380cfb5a0108f79930f5cb6390b83685103b96c32d6a43af392d63ff925a96ef67b57e8de").into(),
        };

        assert_eq!(signed, expected);
    }
}
