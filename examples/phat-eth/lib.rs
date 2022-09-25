#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use pink_extension as pink;
use hex::FromHex;

pub mod transaction;

#[pink::contract(env=PinkEnvironment)]
mod eth_holder {
    use super::*;
    use pink::{http_post, PinkEnvironment};
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use scale::{Decode, Encode};
    use pink::chain_extension::signing as sig;
    use ink_prelude::{
        string::{String, ToString},
        vec::{Vec},
        vec,
        format,
    };
    use serde::Deserialize;
    use serde_json_core::from_slice;
    use core::fmt::Write;

    type Address = [u8; 20];
    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;
    
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
        rpc_nodes: Mapping<String, String>,
        api_key: String,
        is_api_key_set: bool,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct RpcResult<'a> {
        jsonrpc: &'a str,
        result: &'a str,
        id: u32,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        InvalidKey,
        InvalidChain,
        InvalidBody,
        RequestFailed,
        ChainNotConfigured,
        ApiKeyNotSet,
    }

    fn derive_account(salt: &[u8]) -> Result<([u8; 32], [u8; 33], Address)> {
        let privkey_sr25519 = sig::derive_sr25519_key(salt);
        let privkey: [u8; 32] = privkey_sr25519[..32].try_into().expect("Expected a Vec of length 32");
        let pubkey: [u8; 33] = sig::get_public_key(&privkey, sig::SigType::Ecdsa).try_into().expect("Expected a Vec of length 33");
        let mut address = [0; 20];
        ink_env::ecdsa_to_eth_address(&pubkey, &mut address).or(Err(Error::InvalidKey))?;

        Ok((privkey, pubkey, address))
    }

    fn get_chain_id(chain: String) -> Result<u64> {

        let chain_id;
        if chain == "mainnet" { 
            chain_id = 1;
        }
        else if chain == "rinkeby" {
            chain_id = 4;
        }
        else {
            return Err(Error::InvalidChain)
        }
        Ok(chain_id)
    }

    fn to_hex(v: &Vec<u8>) -> String {
        let mut res = "0x".to_string();        
        for a in v.iter() {
            let _res = write!(res, "{:02x}", a);
        }
        res
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

    fn get_next_nonce(rpc_node: &String, account: Address) -> Result<u64> {
        let account_str = to_hex(&account.to_vec());
        let data = format!(
            r#"{{"id":0,"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["{}", "latest"]}}"#,
            account_str
        );

        let resp_body = call_rpc(rpc_node, data.into_bytes())?;
        let (rpc_res, _): (RpcResult, usize) = from_slice(&resp_body).or(Err(Error::InvalidBody))?;
 
        let result = rpc_res.result.to_string();
        let nonce:String = result.chars().skip(2).collect();
        Ok(u64::from_str_radix(&nonce, 16).unwrap())
    }
    
    fn get_gas_price(rpc_node: &String) -> Result<u64> {
        let data = format!(
            r#"{{"id":0,"jsonrpc":"2.0","method":"eth_gasPrice","params":[]}}"#
        );

        let resp_body = call_rpc(rpc_node, data.into_bytes())?;
        let (rpc_res, _): (RpcResult, usize) = from_slice(&resp_body).or(Err(Error::InvalidBody))?;

        let result = rpc_res.result.to_string();
        let gas_price:String = result.chars().skip(2).collect();
        Ok(u64::from_str_radix(&gas_price, 16).unwrap())
    }

    fn send_raw_transaction(rpc_node: &String, raw_tx: &Vec<u8>) -> Result<String> {
        let data = format!(
            r#"{{"id":0,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"]}}"#,
            to_hex(raw_tx)
        );
        let resp_body = call_rpc(rpc_node, data.into_bytes())?;
        let body = String::from_utf8(resp_body).unwrap();
        Ok(body)
    }

    impl EthHolder {
        #[ink(constructor)]
        pub fn new() -> Self {
            ink_lang::utils::initialize_contract(|contract: &mut Self| {
                contract.api_key = Default::default();
                contract.is_api_key_set = false;
            })
        }
    
        #[ink(message)]
        pub fn set_api_key(&mut self, api_key: String) -> Result<()> {
            self.api_key = api_key;
            self.is_api_key_set = true;
            Ok(())
        }

        #[ink(message)]
        pub fn set_chain_info(&mut self, chain: String) -> Result<()> {
            if !self.is_api_key_set {
                return Err(Error::ApiKeyNotSet);
            }

            let http_endpoint = format!(
                "https://{}.infura.io/v3/{}",
                chain, self.api_key
            );
            self.rpc_nodes.insert(&chain, &http_endpoint);
            Ok(())
        }

        #[ink(message)]
        pub fn send_transaction(&self, chain: String, to: String, value: u64) -> Result<String> {
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };

            //step1: get nonce and gas_price.
            let caller = Self::env().caller();
            let salt = caller.as_ref();
            let (priv_key, _, address) = derive_account(salt).unwrap();
            let nonce = get_next_nonce(&rpc_node, address).unwrap();
            let gas_price = get_gas_price(&rpc_node).unwrap();
            let receipt = <Address>::from_hex(to.trim_start_matches("0x")).expect("Decoding address failed");

            let tx = transaction::Transaction {
                nonce: nonce.into(),
                gas: 21_000.into(),
                gas_price: gas_price.into(),
                to: Some(receipt.into()),
                value: value.into(),
                data: Vec::new(),
                transaction_type: None,
            };

            //step2: sign
            let sign_tx: transaction::SignedTransaction = tx.sign(&priv_key, Some(get_chain_id(chain).unwrap()));

            //step3: send
            send_raw_transaction(&rpc_node, &sign_tx.raw_transaction)
        }

        #[ink(message)]
        pub fn get_account(&self) -> Result<([u8; 32], [u8; 33], Address)> {
            let caller = Self::env().caller();
            let salt: &[u8]= caller.as_ref();
            let (privkey, pubkey, address) = derive_account(salt).unwrap();
            Ok((privkey, pubkey, address))
        }

        #[ink(message)]
        pub fn get_nonce(&self, chain: String) -> Result<u64> {
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let caller = Self::env().caller();
            let salt = caller.as_ref();
            let (_, _, address) = derive_account(salt).unwrap();
            let nonce = get_next_nonce(&rpc_node, address);
            nonce
        }

        #[ink(message)]
        pub fn get_gas_price(&self, chain: String) -> Result<u64> {
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let gas_price = get_gas_price(&rpc_node);
            gas_price
        }

    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;
        use openbrush::traits::mock::{Addressable, SharedCallStack};
        use pink::chain_extension::{mock, HttpResponse};
        use hex_literal::hex;

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn end_to_end() { 
            pink_extension_runtime::mock_ext::mock_all_ext();

            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.alice);
            let contract = Addressable::create_native(1, EthHolder::new(), stack.clone());

            //generate account
            mock::mock_derive_sr25519_key(|_| {hex!("9eb2ee60393aeeec31709e256d448c9e40fa64233abf12318f63726e9c417b69").to_vec()});
            let (_, _, address) = derive_account(b"eth-holder").unwrap();
            println!("addr: {:?}", address);
            let expect_addr = hex!("559bfec75ad40e4ff21819bcd1f658cc475c41ba");
            assert_eq!(address, expect_addr);

            //construct chain uri
            let api_key = "2033e5cde24049d4a933778ffefe2457";
            let chain = "rinkeby";
            let _res = contract.call_mut().set_api_key(api_key.to_string());
            let _res = contract.call_mut().set_chain_info(chain.to_string());

            //get nonce
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0x01"}"#.to_vec())
            });
            let nonce = contract.call().get_nonce(chain.to_string()).unwrap();
            println!("nonce: {}", nonce);
            assert_eq!(nonce, 1);

            //get gas price
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0x1dfd14000"}"#.to_vec())
            });
            let gas_price = contract.call().get_gas_price(chain.to_string()).unwrap();
            println!("gas_price: {}", gas_price);
            assert_eq!(gas_price, 8049999872);

            //send raw transaction
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331"}"#.to_vec())
            });
            let tx_raw = hex!("e670ec64341771606e55").to_vec();
            let resp = send_raw_transaction(&chain.to_string(), &tx_raw).unwrap();
            println!("send raw tx resp: {:?}", resp);
        }
    }
}
