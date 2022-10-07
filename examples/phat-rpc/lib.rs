#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

mod era;
mod transaction;

use crate::phat_rpc::{ExtraParam, GenesisHashOk, NextNonceOk, RuntimeVersionOk};
use crate::transaction::{Remark, UnsignedExtrinsic};
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;
use pink_utils::attestation;

#[ink::trait_definition]
pub trait SubmittableOracle {
    #[ink(message)]
    fn admin(&self) -> AccountId;

    #[ink(message)]
    fn verifier(&self) -> attestation::Verifier;

    #[ink(message)]
    fn get_next_nonce(&self, chain: String) -> Result<NextNonceOk, phat_rpc::Error>;

    #[ink(message)]
    fn get_runtime_version(&self, chain: String) -> Result<RuntimeVersionOk, phat_rpc::Error>;

    #[ink(message)]
    fn get_genesis_hash(&self, chain: String) -> Result<GenesisHashOk, phat_rpc::Error>;

    #[ink(message)]
    fn create_transaction(
        &self,
        src: AccountId,
        chain: String,
        account_nonce: NextNonceOk,
        runtime_version: RuntimeVersionOk,
        genesis_hash: GenesisHashOk,
        call_data: UnsignedExtrinsic<Remark>,
        extra_param: ExtraParam,
    ) -> Result<Vec<u8>, crate::phat_rpc::Error>;

    #[ink(message)]
    fn send_transaction(
        &self,
        chain: String,
        tx_hash: Vec<u8>,
    ) -> Result<String, crate::phat_rpc::Error>;
}

#[pink::contract(env=PinkEnvironment)]
mod phat_rpc {
    use super::pink;
    use super::SubmittableOracle;
    use crate::era::Era;
    use pink::{chain_extension::signing::sign, http_post, PinkEnvironment};

    use crate::transaction;
    use crate::transaction::{MultiAddress, MultiSignature, Remark, Signature, UnsignedExtrinsic};
    use base58::ToBase58;
    use core::fmt::Write;
    use ink_prelude::{
        borrow::ToOwned,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use ink_storage::traits::SpreadAllocate;
    use ink_storage::Mapping;
    use pink_extension::chain_extension::SigType;
    use pink_utils::attestation;
    use scale::{Compact, Decode, Encode};
    use serde::Deserialize;
    use serde_json_core::from_slice;
    use sp_core_hashing::blake2_256;
    use ss58_registry::Ss58AddressFormat;

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct PhatRpc {
        admin: AccountId,
        attestation_verifier: attestation::Verifier,
        attestation_generator: attestation::Generator,
        rpc_nodes: Mapping<String, String>,
        chain_account_id: Mapping<String, String>,
        account_public: Mapping<String, attestation::Verifier>,
        account_private: Mapping<String, attestation::Generator>,
        api_key: String,
        is_api_key_set: bool,
    }

    /// Errors that can occur upon calling this contract.
    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        InvalidBody,
        InvalidUrl,
        InvalidSignature,
        RequestFailed,
        NoPermissions,
        ApiKeyNotSet,
        ChainNotConfigured,
        InvalidAccount,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    impl PhatRpc {
        #[ink(constructor)]
        pub fn new() -> Self {
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(b"phat-rpc-attestation-key");
            // Save sender as the contract admin
            let admin = Self::env().caller();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                this.attestation_generator = generator;
                this.attestation_verifier = verifier;
                this.api_key = Default::default();
                this.is_api_key_set = false;
            })
        }

        /// Set the RPC node for parachain.
        #[ink(message)]
        pub fn set_chain_info(&mut self, chain: String) -> core::result::Result<(), Error> {
            let caller = self.env().caller();
            if self.admin != caller {
                return Err(Error::NoPermissions);
            }

            let salt = caller.as_ref();
            if !self.is_api_key_set {
                return Err(Error::ApiKeyNotSet);
            }

            let http_endpoint = format!(
                "https://{}.api.onfinality.io/rpc?apikey={}",
                chain, self.api_key
            );
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(salt);
            let account_public: &[u8] = &verifier.pubkey;
            let version = match Ss58AddressFormat::try_from(chain.as_str()) {
                Ok(version) => version,
                Err(_e) => return Err(Error::InvalidAccount),
            };

            let ident: u16 = u16::from(version) & 0b0011_1111_1111_1111;
            let mut v: Vec<u8> = match ident {
                0..=63 => vec![ident as u8],
                64..=16_383 => {
                    let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
                    let second =
                        ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
                    vec![first | 0b01000000, second]
                }
                _ => unreachable!("masked out the upper two bits; qed"),
            };

            let account_public: &[u8; 32] = account_public.try_into().expect("works");
            v.extend(account_public);
            let r = ss58hash(&v);
            v.extend(&r.as_bytes()[0..2]);
            let account_public_ss58 = v.to_base58();

            self.rpc_nodes.insert(&chain, &http_endpoint);
            self.chain_account_id.insert(&chain, &account_public_ss58);
            self.account_public.insert(&account_public_ss58, &verifier);
            self.account_private
                .insert(&account_public_ss58, &generator);
            Ok(())
        }

        /// Set the user api key for user account.
        #[ink(message)]
        pub fn set_api_key(&mut self, api_key: String) -> core::result::Result<(), Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            self.api_key = api_key;
            self.is_api_key_set = true;
            Ok(())
        }

        #[ink(message)]
        pub fn get_api_key(&self) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            if !self.is_api_key_set {
                return Err(Error::ApiKeyNotSet);
            }
            Ok(self.api_key.clone())
        }

        #[ink(message)]
        pub fn get_rpc_endpoint(&self, chain: String) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            Ok(rpc_node)
        }

        #[ink(message)]
        pub fn get_chain_account_id(&self, chain: String) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = match self.chain_account_id.get(&chain) {
                Some(account_id) => account_id,
                None => return Err(Error::ChainNotConfigured),
            };
            Ok(account_id)
        }
    }

    impl SubmittableOracle for PhatRpc {
        // Queries

        #[ink(message)]
        fn admin(&self) -> AccountId {
            self.admin.clone()
        }

        /// The attestation verifier
        #[ink(message)]
        fn verifier(&self) -> attestation::Verifier {
            self.attestation_verifier.clone()
        }

        /// Get account's next nonce on a specific chain.
        #[ink(message)]
        fn get_next_nonce(&self, chain: String) -> core::result::Result<NextNonceOk, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = match self.chain_account_id.get(&chain) {
                Some(account_id) => account_id,
                None => return Err(Error::ChainNotConfigured),
            };
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let data = format!(
                r#"{{"id":1,"jsonrpc":"2.0","method":"system_accountNextIndex","params":["{}"]}}"#,
                account_id
            )
            .into_bytes();
            let resp_body = call_rpc(&rpc_node, data)?;
            let (next_nonce, _): (NextNonce, usize) =
                serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

            let next_nonce_ok = NextNonceOk {
                next_nonce: next_nonce.result,
            };

            let _result = self.attestation_generator.sign(next_nonce_ok.clone());

            Ok(next_nonce_ok)
        }

        /// Get the chain's runtime version.
        #[ink(message)]
        fn get_runtime_version(
            &self,
            chain: String,
        ) -> core::result::Result<RuntimeVersionOk, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let data = r#"{"id":1, "jsonrpc":"2.0", "method": "state_getRuntimeVersion"}"#
                .to_string()
                .into_bytes();
            let resp_body = call_rpc(&rpc_node, data)?;
            let (runtime_version, _): (RuntimeVersion, usize) =
                serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;
            let runtime_version_result = runtime_version.result;
            let mut api_vec: Vec<(String, u32)> = Vec::new();
            for (api_str, api_u32) in runtime_version_result.apis {
                api_vec.push((api_str.to_string().parse().unwrap(), api_u32));
            }

            let runtime_version_ok = RuntimeVersionOk {
                spec_name: runtime_version_result.specName.to_string().parse().unwrap(),
                impl_name: runtime_version_result.implName.to_string().parse().unwrap(),
                authoring_version: runtime_version_result.authoringVersion,
                spec_version: runtime_version_result.specVersion,
                impl_version: runtime_version_result.implVersion,
                apis: api_vec,
                transaction_version: runtime_version_result.transactionVersion,
                state_version: runtime_version_result.stateVersion,
            };

            let _result = self.attestation_generator.sign(runtime_version_ok.clone());

            Ok(runtime_version_ok)
        }

        /// Get chain's genesis hash
        #[ink(message)]
        fn get_genesis_hash(&self, chain: String) -> core::result::Result<GenesisHashOk, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let data =
                r#"{"id":1, "jsonrpc":"2.0", "method": "chain_getBlockHash","params":["0"]}"#
                    .to_string()
                    .into_bytes();
            let resp_body = call_rpc(&rpc_node, data)?;
            let (genesis_hash, _): (GenesisHash, usize) =
                serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

            let genesis_hash_ok = GenesisHashOk {
                genesis_hash: from_hex(genesis_hash.result).or(Err(Error::InvalidBody))?,
            };

            let _result = self.attestation_generator.sign(genesis_hash_ok.clone());

            Ok(genesis_hash_ok)
        }

        /// Compose a transaction, sign with derived account for the chain, and submit the extrinsic
        /// to the RPC Node with author_submitExtrinsic call
        #[ink(message)]
        fn create_transaction(
            &self,
            src: AccountId,
            chain: String,
            account_nonce: NextNonceOk,
            runtime_version: RuntimeVersionOk,
            genesis_hash: GenesisHashOk,
            call_data: UnsignedExtrinsic<Remark>,
            extra_param: ExtraParam,
        ) -> core::result::Result<Vec<u8>, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = match self.chain_account_id.get(&chain) {
                Some(account_id) => account_id,
                None => return Err(Error::ChainNotConfigured),
            };
            let src_account_id: MultiAddress<AccountId> = transaction::MultiAddress::Id(src);
            let signer = match self.account_private.get(&account_id) {
                Some(signer) => signer,
                None => return Err(Error::ChainNotConfigured),
            };
            let genesis_hash_vec = genesis_hash.genesis_hash;
            //let genesis_hash_raw = genesis_hash_vec[..];

            // Construct our custom additional params.
            let additional_params = (
                runtime_version.spec_version,
                runtime_version.transaction_version,
                genesis_hash_vec.clone(),
                // This should be configurable tx has a lifetime
                genesis_hash_vec,
            );
            // Construct the extra param
            let extra = (
                extra_param.era,
                Compact(account_nonce.next_nonce),
                Compact(extra_param.tip),
            );
            // Construct signature
            let signature = {
                let mut bytes = Vec::new();
                call_data.encode_to(&mut bytes);
                extra.encode_to(&mut bytes);
                additional_params.encode_to(&mut bytes);
                if bytes.len() > 256 {
                    sign(
                        &sp_core_hashing::blake2_256(&bytes),
                        &signer.privkey,
                        SigType::Sr25519,
                    )
                } else {
                    sign(&bytes, &signer.privkey, SigType::Sr25519)
                }
            };
            let signature_bytes: &[u8] = &signature;
            let signature_type =
                Signature::try_from(signature_bytes).or(Err(Error::InvalidSignature))?;
            let multi_signature = MultiSignature::Sr25519(signature_type);
            // Encode Extrinsic
            let extrinsic = {
                let mut encoded_inner = Vec::new();
                // "is signed" + tx protocol v4
                (0b10000000 + 4u8).encode_to(&mut encoded_inner);
                // from address for signature
                src_account_id.encode_to(&mut encoded_inner);
                // the signature bytes
                multi_signature.encode_to(&mut encoded_inner);
                // attach custom extra params
                extra.encode_to(&mut encoded_inner);
                // and now, call data
                call_data.encode_to(&mut encoded_inner);
                // now, prefix byte length:
                let len = Compact(
                    u32::try_from(encoded_inner.len()).expect("extrinsic size expected to be <4GB"),
                );
                let mut encoded = Vec::new();
                len.encode_to(&mut encoded);
                encoded.extend(encoded_inner);
                encoded
            };
            // Encode extrinsic then send RPC Call
            //let extrinsic_hex = vec_to_hex_string(&extrinsic);

            Ok(extrinsic)
        }

        /// Send the transaction to the chain RPC node.
        #[ink(message)]
        fn send_transaction(
            &self,
            chain: String,
            tx_hash: Vec<u8>,
        ) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            // let account_id = match self.chain_account_id.get(&chain) {
            //     Some(account_id) => account_id,
            //     None => return Err(Error::ChainNotConfigured),
            // };
            // let verifier = match self.account_public.get(&account_id) {
            //     Some(verifier) => verifier,
            //     None => return Err(Error::ChainNotConfigured),
            // };
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let tx_hex = vec_to_hex_string(&tx_hash);
            // println!("{:?}", tx_raw);

            let data = format!(
                r#"{{"id":1,"jsonrpc":"2.0","method":"author_submitExtrinsic","params":["{}"]}}"#,
                tx_hex
            )
            .into_bytes();
            let resp_body = call_rpc(&rpc_node, data)?;
            let body = String::from_utf8(resp_body).unwrap();

            Ok(body)
        }
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct NextNonce<'a> {
        jsonrpc: &'a str,
        result: u64,
        id: u32,
    }

    #[derive(Encode, Decode, Clone, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct NextNonceOk {
        next_nonce: u64,
    }

    #[derive(Deserialize, Debug)]
    pub struct RuntimeVersion<'a> {
        jsonrpc: &'a str,
        #[serde(borrow)]
        result: RuntimeVersionResult<'a>,
        id: u32,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    #[serde(bound(deserialize = "ink_prelude::vec::Vec<(&'a str, u32)>: Deserialize<'de>"))]
    pub struct RuntimeVersionResult<'a> {
        specName: &'a str,
        implName: &'a str,
        authoringVersion: u32,
        specVersion: u32,
        implVersion: u32,
        #[serde(borrow)]
        apis: Vec<(&'a str, u32)>,
        transactionVersion: u32,
        stateVersion: u32,
    }

    #[derive(Encode, Decode, Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct RuntimeVersionOk {
        spec_name: String,
        impl_name: String,
        authoring_version: u32,
        spec_version: u32,
        impl_version: u32,
        apis: Vec<(String, u32)>,
        transaction_version: u32,
        state_version: u32,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct GenesisHash<'a> {
        jsonrpc: &'a str,
        result: &'a str,
        id: u32,
    }

    #[derive(Encode, Decode, Clone, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct GenesisHashOk {
        genesis_hash: Vec<u8>,
    }

    #[derive(Encode, Decode, Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ExtraParam {
        // 0 if Immortal, or Vec<u64, u64> for period and the phase.
        era: Era,
        // Tip for the block producer.
        tip: u128,
    }

    /// Wraps an already encoded byte vector, prevents being encoded as a raw byte vector as part of
    /// the transaction payload
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Encoded(pub Vec<u8>);

    impl scale::Encode for Encoded {
        fn encode(&self) -> Vec<u8> {
            self.0.to_owned()
        }
    }

    /// Decoding bytes from hex string error.
    #[derive(Debug, PartialEq, Eq)]
    pub enum FromHexError {
        /// The `0x` prefix is missing.
        MissingPrefix,
        /// Invalid (non-hex) character encountered.
        InvalidHex {
            /// The unexpected character.
            character: char,
            /// Index of that occurrence.
            index: usize,
        },
    }

    impl core::fmt::Display for FromHexError {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            match *self {
                Self::MissingPrefix => write!(fmt, "0x prefix is missing"),
                Self::InvalidHex { character, index } => {
                    write!(fmt, "invalid hex character: {}, at {}", character, index)
                }
            }
        }
    }

    /// Decode given hex string into a vector of bytes.
    ///
    /// Returns an error if the string is not prefixed with `0x`
    /// or non-hex characters are present.
    pub fn from_hex(v: &str) -> core::result::Result<Vec<u8>, FromHexError> {
        if !v.starts_with("0x") {
            return Err(FromHexError::MissingPrefix);
        }

        let mut bytes = vec![0u8; (v.len() - 1) / 2];
        from_hex_raw(v, &mut bytes)?;
        Ok(bytes)
    }

    /// Decode given 0x-prefixed hex string into provided slice.
    /// Used internally by `from_hex` and `deserialize_check_len`.
    ///
    /// The method will panic if:
    /// 1. `v` is shorter than 2 characters (you need to check 0x prefix outside).
    /// 2. `bytes` have incorrect length (make sure to allocate enough beforehand).
    fn from_hex_raw<'a>(v: &str, bytes: &mut [u8]) -> core::result::Result<usize, FromHexError> {
        let bytes_len = v.len() - 2;
        let mut modulus = bytes_len % 2;
        let mut buf = 0;
        let mut pos = 0;
        for (index, byte) in v.bytes().enumerate().skip(2) {
            buf <<= 4;

            match byte {
                b'A'..=b'F' => buf |= byte - b'A' + 10,
                b'a'..=b'f' => buf |= byte - b'a' + 10,
                b'0'..=b'9' => buf |= byte - b'0',
                b' ' | b'\r' | b'\n' | b'\t' => {
                    buf >>= 4;
                    continue;
                }
                b => {
                    let character = char::from(b);
                    return Err(FromHexError::InvalidHex { character, index });
                }
            }

            modulus += 1;
            if modulus == 2 {
                modulus = 0;
                bytes[pos] = buf;
                pos += 1;
            }
        }

        Ok(pos)
    }

    fn call_rpc(rpc_node: &String, data: Vec<u8>) -> Result<Vec<u8>> {
        let content_length = format!("{}", data.len());
        let headers: Vec<(String, String)> = vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), content_length),
        ];

        let response = http_post!(rpc_node, data, headers);
        if response.status_code != 200 {
            return Err(Error::RequestFailed);
        }

        let body = response.body;
        Ok(body)
    }

    fn vec_to_hex_string(v: &Vec<u8>) -> String {
        let mut res = "0x".to_string();
        for a in v.iter() {
            write!(res, "{:02x}", a).expect("should create hex string");
        }
        res
    }

    const PREFIX: &[u8] = b"SS58PRE";

    fn ss58hash(data: &[u8]) -> blake2_rfc::blake2b::Blake2bResult {
        let mut context = blake2_rfc::blake2b::Blake2b::new(64);
        context.update(PREFIX);
        context.update(data);
        context.finalize()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hex_literal::hex;
        use ink_lang as ink;
        use openbrush::traits::mock::{Addressable, SharedCallStack};
        use pink::chain_extension::{mock, HttpResponse};

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn end_to_end() {
            pink_extension_runtime::mock_ext::mock_all_ext();

            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.alice);
            let contract = Addressable::create_native(1, PhatRpc::new(), stack.clone());

            let chain = "kusama";
            let test_api_key = "281e1234-ec43-7826-d839-81b6c627b673";
            let _res = contract.call_mut().set_api_key(test_api_key.to_string());
            let get_api_key = contract.call().get_api_key().expect("okay");
            assert_eq!(test_api_key, get_api_key);
            //generate account
            mock::mock_derive_sr25519_key(|_| {
                hex!("9eb2ee60393aeeec31709e256d448c9e40fa64233abf12318f63726e9c417b69").to_vec()
            });
            let res = contract.call_mut().set_chain_info(chain.to_string());
            let address = contract
                .call()
                .get_chain_account_id(chain.to_string())
                .unwrap();
            println!("addr: {:?}", address);
            let expect_addr = "FXJFWSVDcyVi3bTy8D9ESznQM4JoNBRQLEjWFgAGnGQfpbR".to_string();
            assert_eq!(address, expect_addr);

            //get nonce
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","result":0,"id":1}"#.to_vec())
            });
            let nonce = contract.call().get_next_nonce(chain.to_string()).unwrap();
            println!("nonce: {:?}", nonce.next_nonce);
            assert_eq!(nonce.next_nonce, 0);

            //get runtime version
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{
                "jsonrpc":"2.0","result":{"specName":"kusama","implName":"parity-kusama","authoringVersion":2,"specVersion":9230,"implVersion":0,"apis":[["0xdf6acb689907609b",4],["0x37e397fc7c91f5e4",1],["0x40fe3ad401f8959a",6],["0xd2bc9897eed08f15",3],["0xf78b278be53f454c",2],["0xaf2c0297a23e6d3d",2],["0x49eaaf1b548a0cb0",1],["0x91d5df18b0d2cf58",1],["0xed99c5acb25eedf5",3],["0xcbca25e39f142387",2],["0x687ad44ad37f03c2",1],["0xab3c0572291feb8b",1],["0xbc9d89904f5b923f",1],["0x37c8bb1350a9a2a8",1]],"transactionVersion":11,"stateVersion":0},"id":1
            }"#.to_vec())
            });
            let runtime_version = contract
                .call()
                .get_runtime_version(chain.to_string())
                .unwrap();
            println!("runtime_version: {:?}", runtime_version);
            //assert_eq!(gas_price, 8049999872);
            // get genesis hash
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{
                "jsonrpc":"2.0","result":"0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe","id":1
            }"#.to_vec())
            });
            let genesis_hash = contract.call().get_genesis_hash(chain.to_string()).unwrap();
            println!("genesis_hash: {:?}", genesis_hash);
            assert_eq!(
                genesis_hash.genesis_hash,
                from_hex("0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe")
                    .unwrap()
            );
            // Extra params for transaction creation
            let extra = ExtraParam {
                era: Era::Immortal,
                tip: 0,
            };
            // Remark Call
            let remark: String = "hi how are ya".to_string();
            let call_param = transaction::UnsignedExtrinsic {
                pallet_id: 0u8,
                call_id: 1u8,
                call: transaction::Remark { remark },
            };

            //create raw transaction
            let tx_raw = contract
                .call()
                .create_transaction(
                    accounts.alice,
                    chain.to_string(),
                    nonce,
                    runtime_version,
                    genesis_hash,
                    call_param,
                    extra,
                )
                .unwrap();
            println!("{:?}", tx_raw);
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331"}"#.to_vec())
            });

            let _resp = contract
                .call()
                .send_transaction(chain.to_string(), tx_raw)
                .unwrap();
        }
    }
}
