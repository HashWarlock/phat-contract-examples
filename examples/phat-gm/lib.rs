#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

mod era;

use crate::phat_gm::{CurrencyId, Error, ExtraParam, GenesisHashOk, NextNonceOk, RuntimeVersionOk};
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
    fn get_next_nonce(&self) -> Result<NextNonceOk, Error>;

    #[ink(message)]
    fn get_runtime_version(&self) -> Result<RuntimeVersionOk, Error>;

    #[ink(message)]
    fn get_genesis_hash(&self) -> Result<GenesisHashOk, Error>;

    #[ink(message)]
    fn create(
        &self,
        src: AccountId,
        dest: AccountId,
        token: CurrencyId,
        amount: u128,
        account_nonce: NextNonceOk,
        runtime_version: RuntimeVersionOk,
        genesis_hash: GenesisHashOk,
        extra_param: ExtraParam,
    ) -> Result<String, Error>;

    #[ink(message)]
    fn send(&self, tx_hash: String) -> Result<String, Error>;
}

#[pink::contract(env=PinkEnvironment)]
mod phat_gm {
    use super::pink;
    use super::SubmittableOracle;
    use crate::era::Era;
    use pink::{http_post, PinkEnvironment};

    use crate::ink;
    use base58::ToBase58;
    use core::fmt::Display;
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
    use pink_utils::attestation;
    use scale::{Compact, Decode, Encode};
    use serde::Deserialize;
    use serde_json_core::from_slice;
    use sp_core_hashing::blake2_256;
    use ss58_registry::Ss58AddressFormat;

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct PhatGM {
        admin: AccountId,
        attestation_verifier: attestation::Verifier,
        attestation_generator: attestation::Generator,
        rpc_node: String,
        chain_account_id: String,
        account_public: Mapping<String, attestation::Verifier>,
        account_private: Mapping<String, attestation::Generator>,
    }

    /// Errors that can occur upon calling this contract.
    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        InvalidBody,
        InvalidUrl,
        InvalidSignature,
        InvalidAccount,
        RequestFailed,
        NoPermissions,
        NoGMAccountDetected,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    impl PhatGM {
        #[ink(constructor)]
        pub fn new() -> Self {
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(b"phat-gm-attestation-key");
            // Save sender as the contract admin
            let admin = Self::env().caller();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                this.attestation_generator = generator;
                this.attestation_verifier = verifier;
                this.chain_account_id = Default::default();
                this.rpc_node = Default::default();
            })
        }

        /// Set the RPC node for parachain.
        #[ink(message)]
        pub fn set_gm_info(&mut self, rpc_node: String) -> core::result::Result<(), Error> {
            let caller = self.env().caller();
            if self.admin != caller {
                return Err(Error::NoPermissions);
            }

            let salt = caller.as_ref();
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(salt);
            let account_public: &[u8] = &verifier.pubkey;
            let version = match Ss58AddressFormat::try_from("gm") {
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

            self.rpc_node = rpc_node;
            self.chain_account_id = account_public_ss58.clone();
            self.account_public.insert(&account_public_ss58, &verifier);
            self.account_private
                .insert(&account_public_ss58, &generator);
            Ok(())
        }

        #[ink(message)]
        pub fn get_rpc_endpoint(&self) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = self.rpc_node.clone();
            Ok(rpc_node)
        }

        #[ink(message)]
        pub fn get_chain_account_id(&self) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = self.chain_account_id.clone();
            if account_id == "" {
                return Err(Error::NoGMAccountDetected);
            }
            Ok(account_id)
        }
    }

    impl SubmittableOracle for PhatGM {
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
        fn get_next_nonce(&self) -> core::result::Result<NextNonceOk, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = self.chain_account_id.clone();
            let rpc_node = &self.rpc_node;
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
        fn get_runtime_version(&self) -> core::result::Result<RuntimeVersionOk, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = &self.rpc_node;
            let data = r#"{"id":1, "jsonrpc":"2.0", "method": "state_getRuntimeVersion"}"#
                .to_string()
                .into_bytes();
            let resp_body = call_rpc(rpc_node, data)?;
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
        fn get_genesis_hash(&self) -> core::result::Result<GenesisHashOk, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = &self.rpc_node;
            let data =
                r#"{"id":1, "jsonrpc":"2.0", "method": "chain_getBlockHash","params":["0"]}"#
                    .to_string()
                    .into_bytes();
            let resp_body = call_rpc(rpc_node, data)?;
            let (genesis_hash, _): (GenesisHash, usize) =
                serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

            let genesis_hash_string = GenesisHashOk {
                genesis_hash: genesis_hash.result.to_string().parse().unwrap(),
            };

            let _result = self.attestation_generator.sign(genesis_hash_string.clone());

            Ok(genesis_hash_string)
        }

        /// Compose a transaction, sign with derived account for the chain, and submit the extrinsic
        /// to the RPC Node with author_submitExtrinsic call
        #[ink(message)]
        fn create(
            &self,
            src: AccountId,
            dest: AccountId,
            token: CurrencyId,
            amount: u128,
            account_nonce: NextNonceOk,
            runtime_version: RuntimeVersionOk,
            genesis_hash: GenesisHashOk,
            extra_param: ExtraParam,
        ) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = self.chain_account_id.clone();
            let account_id_vec = match self.account_public.get(&account_id) {
                Some(verifier) => verifier.pubkey,
                None => return Err(Error::NoGMAccountDetected),
            };

            let raw_account: MultiAddress<AccountId, u32> = MultiAddress::Id(src);
            //let src_account_id: Vec<u8> = account_id.as_bytes().into();
            let signer = match self.account_private.get(&account_id) {
                Some(signer) => signer,
                None => return Err(Error::NoGMAccountDetected),
            };

            let raw_call_data = UnsignedExtrinsic {
                pallet_id: 0x0d,
                call_id: 0x00,
                call: Transfer {
                    dest: MultiAddress::Raw(account_id_vec),
                    currency_id: token,
                    amount: Compact(amount),
                },
            };

            //println!("{:?}", vec_to_hex_string(&raw_call_data.encode()));

            // Construct our custom additional params.
            let additional_params = (
                runtime_version.spec_version,
                runtime_version.transaction_version,
                genesis_hash.genesis_hash.clone(),
                // This should be configurable tx has a lifetime
                genesis_hash.genesis_hash,
            );
            // Construct the extra param
            let extra = Extra {
                era: extra_param.era,
                nonce: Compact(account_nonce.next_nonce),
                tip: Compact(extra_param.tip),
            };
            let payload = (&raw_call_data.encode(), &extra, &additional_params);
            // Construct signature
            let signature = {
                let mut bytes = Vec::new();
                payload.encode_to(&mut bytes);
                if bytes.len() > 256 {
                    signer.sign(sp_core_hashing::blake2_256(&bytes)).signature
                } else {
                    signer.sign(bytes).signature
                }
            };

            let extr_sig = SignedExtrinsic {
                address: raw_account,
                signature,
                extra,
                call: raw_call_data,
            };
            // Encode Extrinsic
            let extrinsic = {
                let mut encoded_inner = Vec::new();
                // "is signed" + tx protocol v4
                (0b10000000 + 4u8).encode_to(&mut encoded_inner);
                extr_sig.encode_to(&mut encoded_inner);
                // from address for signature
                // raw_account.encode_to(&mut encoded_inner);
                // // the signature bytes
                // signature.encode_to(&mut encoded_inner);
                // // attach custom extra params
                // extra.encode_to(&mut encoded_inner);
                // // and now, call data
                // raw_call_data.encode_to(&mut encoded_inner);
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
            //let extrinsic_enc = Encoded(extrinsic);
            let extrinsic_hex = vec_to_hex_string(&extrinsic);

            Ok(extrinsic_hex)
        }

        /// Send the transaction to the chain RPC node.
        #[ink(message)]
        fn send(&self, tx_hash: String) -> core::result::Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = &self.rpc_node;
            let data = format!(
                r#"{{"id":1,"jsonrpc":"2.0","method":"author_submitExtrinsic","params":["{}"]}}"#,
                tx_hash
            )
            .into_bytes();
            let resp_body = call_rpc(rpc_node, data)?;
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
        genesis_hash: String,
    }

    #[derive(Encode, Decode, Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ExtraParam {
        // 0 if Immortal, or Vec<u64, u64> for period and the phase.
        era: Era,
        // Tip for the block producer.
        tip: u128,
    }

    #[derive(Encode, Decode, Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct CallParam {
        // pallet index
        pallet_index: u8,
        // pallet index call
        pallet_call: u8,
        // pallet call data
        call_data: Vec<u8>,
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

    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    struct UnsignedExtrinsic<Call> {
        pallet_id: u8,
        call_id: u8,
        call: Call,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    struct Transfer {
        dest: MultiAddress<AccountId, u32>,
        currency_id: CurrencyId,
        amount: Compact<Balance>,
    }

    #[derive(Encode, Decode, Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Extra {
        // 0 if Immortal, or Vec<u64, u64> for period and the phase.
        era: Era,
        // Nonce
        nonce: Compact<u64>,
        // Tip for the block producer.
        tip: Compact<u128>,
    }

    /// A multi-format address wrapper for on-chain accounts.
    #[derive(Encode, Decode, PartialEq, Eq, Clone, Debug, scale_info::TypeInfo)]
    #[cfg_attr(feature = "std", derive(Hash))]
    pub enum MultiAddress<AccountId, AccountIndex> {
        /// It's an account ID (pubkey).
        Id(AccountId),
        /// It's an account index.
        Index(#[codec(compact)] AccountIndex),
        /// It's some arbitrary raw bytes.
        Raw(Vec<u8>),
        /// It's a 32 byte representation.
        Address32([u8; 32]),
        /// Its a 20 byte representation.
        Address20([u8; 20]),
    }

    impl<AccountId, AccountIndex> From<AccountId> for MultiAddress<AccountId, AccountIndex> {
        fn from(a: AccountId) -> Self {
            Self::Id(a)
        }
    }

    #[derive(Encode, Decode, PartialEq, Eq, Clone, Debug, scale_info::TypeInfo)]
    #[cfg_attr(feature = "std", derive(Hash))]
    pub enum MultiSignature<Signature> {
        /// An Ed25519 signature.
        Ed25519(Signature),
        /// An Sr25519 signature.
        Sr25519(Signature),
        /// An ECDSA/SECP256k1 signature.
        Ecdsa(Signature),
    }

    #[derive(Encode, Decode, PartialEq, Eq, Clone, Copy, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum CurrencyId {
        FREN,
        GM,
        GN,
    }

    #[derive(Encode, Decode, PartialEq, Eq, Clone, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedExtrinsic {
        address: MultiAddress<AccountId, u32>,
        signature: Vec<u8>,
        extra: Extra,
        call: UnsignedExtrinsic<Transfer>,
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
            let contract = Addressable::create_native(1, PhatGM::new(), stack.clone());

            let chain = "gm";
            //generate account
            mock::mock_derive_sr25519_key(|_| {
                hex!("9eb2ee60393aeeec31709e256d448c9e40fa64233abf12318f63726e9c417b69").to_vec()
            });
            let res = contract
                .call_mut()
                .set_gm_info("https://kusama.gmordie.com/rpc".to_string());
            let address = contract.call().get_chain_account_id().unwrap();
            println!("addr: {:?}", address);
            let expect_addr = "gMWwzZffNvKiJ7fs4kv3RDA1M9sv7AJUfxMbtizouu1sXt5CX".to_string();
            assert_eq!(address, expect_addr);

            //get nonce
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","result":0,"id":1}"#.to_vec())
            });
            let nonce = contract.call().get_next_nonce().unwrap();
            println!("nonce: {:?}", nonce.next_nonce);
            assert_eq!(nonce.next_nonce, 0);

            //get runtime version
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{
                "jsonrpc":"2.0","result":{"specName":"template-parachain","implName":"template-parachain","authoringVersion":1,"specVersion":6,"implVersion":0,"apis":[["0xdf6acb689907609b",4],["0x37e397fc7c91f5e4",1],["0x40fe3ad401f8959a",6],["0xd2bc9897eed08f15",3],["0xf78b278be53f454c",2],["0xaf2c0297a23e6d3d",2],["0x49eaaf1b548a0cb0",1],["0x91d5df18b0d2cf58",1],["0xed99c5acb25eedf5",3],["0xcbca25e39f142387",2],["0x687ad44ad37f03c2",1],["0xab3c0572291feb8b",1],["0xbc9d89904f5b923f",1],["0x37c8bb1350a9a2a8",1]],"transactionVersion":11,"stateVersion":0},"id":1
            }"#.to_vec())
            });
            let runtime_version = contract.call().get_runtime_version().unwrap();
            println!("runtime_version: {:?}", runtime_version);
            //assert_eq!(gas_price, 8049999872);
            // get genesis hash
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{
                "jsonrpc":"2.0","result":"0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe","id":1
            }"#.to_vec())
            });
            let genesis_hash = contract.call().get_genesis_hash().unwrap();
            println!("genesis_hash: {:?}", genesis_hash);
            assert_eq!(
                genesis_hash.genesis_hash,
                "0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe".to_string()
            );
            // Extra params for transaction creation
            let extra = ExtraParam {
                era: Era::Immortal,
                tip: 0,
            };

            //create raw transaction
            let tx_raw = contract
                .call()
                .create(
                    accounts.alice,
                    accounts.bob,
                    CurrencyId::GM,
                    1u128,
                    nonce,
                    runtime_version,
                    genesis_hash,
                    extra,
                )
                .unwrap();
            println!("{:?}", tx_raw);
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331"}"#.to_vec())
            });

            let _resp = contract.call().send(tx_raw).unwrap();
        }
    }
}
