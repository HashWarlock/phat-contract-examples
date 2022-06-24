#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod phat_rpc {
    use super::pink;
    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use pink::{http_post, PinkEnvironment};
    use scale::{Decode, Encode};
    use serde::Deserialize;
    use serde_json_core::from_slice;

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    pub struct PhatRpc {
        admin: AccountId,
        rpc_nodes: Mapping<String, String>,
        chain_account_id: Mapping<String, String>,
        api_key: String,
        is_api_key_set: bool,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        InvalidBody,
        InvalidUrl,
        InvalidSignature,
        RequestFailed,
        NoPermissions,
        ApiKeyNotSet,
        ChainNotConfigured,
    }

    impl PhatRpc {
        #[ink(constructor)]
        pub fn new() -> Self {
            // Save sender as the contract admin
            let admin = Self::env().caller();
            // This call is required in order to correctly initialize the
            // `Mapping`s of our contract.
            ink_lang::codegen::initialize_contract(|contract: &mut Self| {
                contract.admin = admin;
                contract.api_key = Default::default();
                contract.is_api_key_set = false;
            })
        }

        /// Set the RPC node for parachain.
        #[ink(message)]
        pub fn set_chain_info(&mut self, chain: String, account_id: String) -> Result<(), Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            if !self.is_api_key_set {
                return Err(Error::ApiKeyNotSet);
            }

            let http_endpoint = format!(
                "https://{}.api.onfinality.io/rpc\\?apikey\\={}",
                chain, self.api_key
            );
            self.rpc_nodes.insert(&chain, &http_endpoint);
            self.chain_account_id.insert(&chain, &account_id);
            Ok(())
        }

        /// Set the user api key for user account.
        #[ink(message)]
        pub fn set_api_key(&mut self, api_key: String) -> Result<(), Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            self.api_key = api_key;
            self.is_api_key_set = true;
            Ok(())
        }

        /// Get account's next nonce on a specific chain.
        #[ink(message)]
        pub fn get_next_nonce(&self, chain: String) -> Result<u32, Error> {
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
            // Get next nonce for the account through HTTP request
            let response = http_post!(rpc_node, data);
            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }
            let body = response.body;
            let (next_nonce, _): (NextNonce, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidBody))?;

            Ok(next_nonce.result)
        }

        /// Get the chain's runtime version.
        #[ink(message)]
        pub fn get_runtime_version(&self, chain: String) -> Result<RuntimeVersionOk, Error> {
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
            let data = r#"{"id":1, "jsonrpc":"2.0", "method": "state_getRuntimeVersion"}"#
                .to_string()
                .into_bytes();
            // Get next nonce for the account through HTTP request
            let response = http_post!(rpc_node, data);
            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }
            let body = response.body;
            let (runtime_version, _): (RuntimeVersion, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidBody))?;
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

            Ok(runtime_version_ok)
        }

        /// Get chain's genesis hash
        #[ink(message)]
        pub fn get_genesis_hash(&self, chain: String) -> Result<String, Error> {
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
            let data =
                r#"{"id":1, "jsonrpc":"2.0", "method": "chain_getBlockHash","params":["0"]}"#
                    .to_string()
                    .into_bytes();
            // Get next nonce for the account through HTTP request
            let response = http_post!(rpc_node, data);
            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }
            let body = response.body;
            let (genesis_hash, _): (GenesisHash, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidBody))?;

            let genesis_hash_string = genesis_hash.result.to_string().parse().unwrap();

            Ok(genesis_hash_string)
        }

        #[ink(message)]
        pub fn get_api_key(&self) -> Result<String, Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            if !self.is_api_key_set {
                return Err(Error::ApiKeyNotSet);
            }
            Ok(self.api_key.clone())
        }

        #[ink(message)]
        pub fn get_rpc_endpoint(&self, chain: String) -> Result<String, Error> {
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
        pub fn get_chain_account_id(&self, chain: String) -> Result<String, Error> {
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

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct NextNonce<'a> {
        jsonrpc: &'a str,
        result: u32,
        id: u32,
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct NextNonceOk {
        next_nonce: u32,
    }

    #[derive(Deserialize, Debug)]
    pub struct RuntimeVersion<'a> {
        jsonrpc: &'a str,
        #[serde(borrow)]
        result: RuntimeVersionResult<'a>,
        id: u32,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    #[serde(bound(deserialize = "alloc::vec::Vec<(&'a str, u32)>: Deserialize<'de>"))]
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

    #[derive(Encode, Decode, Debug, PartialEq)]
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

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct GenesisHashOk {
        genesis_hash: String,
    }

    pub fn extract_next_nonce(body: &[u8]) -> Result<u32, Error> {
        let (next_nonce, _): (NextNonce, usize) = serde_json_core::from_slice(body).unwrap();
        let result = next_nonce.result;
        Ok(result)
    }

    pub fn extract_runtime_version(body: &[u8]) -> Result<RuntimeVersionOk, Error> {
        let (runtime_version, _): (RuntimeVersion, usize) =
            serde_json_core::from_slice(body).unwrap();
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
        Ok(runtime_version_ok)
    }

    pub fn extract_genesis_hash(body: &[u8]) -> Result<String, Error> {
        let (genesis_hash, _): (GenesisHash, usize) = serde_json_core::from_slice(body).unwrap();
        let result = genesis_hash.result.to_string().parse().unwrap();
        Ok(result)
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        #[ink::test]
        fn can_parse_next_nonce() {
            let response = r#"{
                "jsonrpc":"2.0","result":238,"id":1
            }"#;
            let result = extract_next_nonce(response.as_bytes());

            assert_eq!(result, Ok(238));
        }

        #[ink::test]
        fn can_parse_runtime_version() {
            let response = r#"{
                "jsonrpc":"2.0","result":{"specName":"kusama","implName":"parity-kusama","authoringVersion":2,"specVersion":9230,"implVersion":0,"apis":[["0xdf6acb689907609b",4],["0x37e397fc7c91f5e4",1],["0x40fe3ad401f8959a",6],["0xd2bc9897eed08f15",3],["0xf78b278be53f454c",2],["0xaf2c0297a23e6d3d",2],["0x49eaaf1b548a0cb0",1],["0x91d5df18b0d2cf58",1],["0xed99c5acb25eedf5",3],["0xcbca25e39f142387",2],["0x687ad44ad37f03c2",1],["0xab3c0572291feb8b",1],["0xbc9d89904f5b923f",1],["0x37c8bb1350a9a2a8",1]],"transactionVersion":11,"stateVersion":0},"id":1
            }"#;
            let result = extract_runtime_version(response.as_bytes());
            let exp_result = RuntimeVersionOk {
                spec_name: "kusama".to_string(),
                impl_name: "parity-kusama".to_string(),
                authoring_version: 2,
                spec_version: 9230,
                impl_version: 0,
                apis: vec![
                    ("0xdf6acb689907609b".to_string(), 4),
                    ("0x37e397fc7c91f5e4".to_string(), 1),
                    ("0x40fe3ad401f8959a".to_string(), 6),
                    ("0xd2bc9897eed08f15".to_string(), 3),
                    ("0xf78b278be53f454c".to_string(), 2),
                    ("0xaf2c0297a23e6d3d".to_string(), 2),
                    ("0x49eaaf1b548a0cb0".to_string(), 1),
                    ("0x91d5df18b0d2cf58".to_string(), 1),
                    ("0xed99c5acb25eedf5".to_string(), 3),
                    ("0xcbca25e39f142387".to_string(), 2),
                    ("0x687ad44ad37f03c2".to_string(), 1),
                    ("0xab3c0572291feb8b".to_string(), 1),
                    ("0xbc9d89904f5b923f".to_string(), 1),
                    ("0x37c8bb1350a9a2a8".to_string(), 1),
                ],
                transaction_version: 11,
                state_version: 0,
            };

            assert_eq!(result, Ok(exp_result));
        }

        #[ink::test]
        fn can_parse_genesis_hash() {
            let response = r#"{
                "jsonrpc":"2.0","result":"0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe","id":1
            }"#;
            let result = extract_genesis_hash(response.as_bytes());

            assert_eq!(
                result,
                Ok(
                    "0xb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe"
                        .to_string()
                )
            );
        }
    }
}
