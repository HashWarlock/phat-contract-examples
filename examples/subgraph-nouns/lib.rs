#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod nouns_subgraph {
    use super::pink;
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };
    use pink::{
        chain_extension::SigType, derive_sr25519_key, get_public_key, http_post, sign, verify,
        PinkEnvironment,
    };
    use scale::{Decode, Encode};
    use serde::Deserialize;
    use serde_json_core::from_slice;

    #[ink(storage)]
    #[derive(Default)]
    pub struct NounsSubgraph {
        admin: AccountId,
        attestation_privkey: Vec<u8>,
        attestation_pubkey: Vec<u8>,
        nouns_id: u32,
        current_bid: u64,
        acceptable_price: u64,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        InvalidBody,
        InvalidUrl,
        InvalidSignature,
        RequestFailed,
        AuctionAlreadySettled,
        MustGetLatestNounInfo,
        NoPermissions,
    }

    impl NounsSubgraph {
        #[ink(constructor)]
        pub fn default() -> Self {
            // Generate a Sr25519 key pair
            let privkey = derive_sr25519_key!(b"gist-attestation-key");
            let pubkey = get_public_key!(&privkey, SigType::Sr25519);
            // Save sender as the contract admin
            let admin = Self::env().caller();
            Self {
                admin,
                attestation_privkey: privkey,
                attestation_pubkey: pubkey,
                nouns_id: 0,
                current_bid: 0,
                acceptable_price: 0,
            }
        }

        /// Set the acceptable price that the admin is comfortable bidding for a Noun.
        #[ink(message)]
        pub fn set_acceptable_price(&mut self, acceptable_price: u64) -> Result<(), Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            self.acceptable_price = acceptable_price * 1000000000000000000;
            Ok(())
        }

        /// Set the last time admin queried for the latest Nouns bid price.
        #[ink(message)]
        pub fn set_nouns_info(&mut self, nouns_info_fe: NounsInfoFE) -> Result<(), Error> {
            let settled = nouns_info_fe.settled;
            // Verify the Nouns Info
            let (nouns_id, current_bid) = self.verify_nouns_info(nouns_info_fe)?;
            // If auction is settled then we cannot purchase the noun
            if settled {
                return Err(Error::AuctionAlreadySettled);
            }

            self.nouns_id = nouns_id;
            self.current_bid = current_bid;

            Ok(())
        }

        /// Check if the current bid price is affordable
        #[ink(message)]
        pub fn is_noun_affordable(&self) -> Result<bool, Error> {
            if self.current_bid == 0 {
                return Err(Error::MustGetLatestNounInfo);
            }
            if self.current_bid < self.acceptable_price {
                Ok(true)
            } else {
                Ok(false)
            }
        }

        #[ink(message)]
        pub fn get_current_bid(&self) -> u64 {
            self.current_bid
        }

        #[ink(message)]
        pub fn get_acceptable_price(&self) -> u64 {
            self.acceptable_price
        }

        #[ink(message)]
        pub fn get_nouns_id(&self) -> u32 {
            self.nouns_id
        }

        /// Get the latest bid price on the current Noun up for auction. Sign the info & return the result.
        #[ink(message)]
        pub fn get_latest_nouns_info(&self) -> Result<NounsInfoFE, Error> {
            // Get the latest nouns info through http_post
            let response = http_post!(NOUNS_HTTP_ENDPOINT, HTTP_POST_DATA.as_bytes().to_vec());
            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }
            let body = response.body;
            // Extract Nouns Info
            let (data, _): (Data, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidBody))?;
            let nouns_info = data.data.auctions[0].clone();

            if nouns_info.settled {
                return Err(Error::AuctionAlreadySettled);
            }
            let nouns_id = nouns_info.id.to_string().parse().unwrap();
            let current_bid = nouns_info.amount.to_string().parse().unwrap();
            let settled = nouns_info.settled;

            let encoded = Encode::encode(&nouns_info);
            let signature = sign!(&encoded, &self.attestation_privkey, SigType::Sr25519);

            let nouns_info_fe = NounsInfoFE {
                id: nouns_id,
                amount: current_bid,
                settled,
                signature,
            };

            Ok(nouns_info_fe)
        }

        /// Verifies the signed nouns_info and return the inner data.
        pub fn verify_nouns_info(&self, nouns_info_fe: NounsInfoFE) -> Result<(u32, u64), Error> {
            let nouns_id: u32 = nouns_info_fe.id.parse().unwrap();
            let current_bid: u64 = nouns_info_fe.amount.parse().unwrap();
            let id: &str = nouns_info_fe.id.as_str();
            let amount: &str = nouns_info_fe.amount.as_str();
            let signature = nouns_info_fe.signature;
            let settled = false;
            let nouns_info = NounsInfo {
                id,
                amount,
                settled,
            };
            let encoded = Encode::encode(&nouns_info);
            if !verify!(
                &encoded,
                &self.attestation_pubkey,
                &signature,
                SigType::Sr25519
            ) {
                return Err(Error::InvalidSignature);
            }
            Ok((nouns_id, current_bid))
        }
    }

    pub const HTTP_POST_DATA: &str = r#"{"query":"query MyQuery {\n  auctions(orderBy: endTime, orderDirection: desc, first: 1) {\n    amount\n    id\n  settled\n}\n}\n","variables":null,"operationName":"MyQuery"}"#;
    pub const NOUNS_HTTP_ENDPOINT: &str =
        "https://api.thegraph.com/subgraphs/name/nounsdao/nouns-subgraph";

    #[derive(Deserialize, Debug)]
    pub struct Data<'a> {
        #[serde(borrow)]
        data: DataInfo<'a>,
    }
    #[derive(Deserialize, Debug)]
    #[serde(bound(deserialize = "alloc::vec::Vec<NounsInfo<'a>>: Deserialize<'de>"))]
    pub struct DataInfo<'a> {
        #[serde(borrow)]
        auctions: Vec<NounsInfo<'a>>,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct NounsInfo<'a> {
        id: &'a str,
        amount: &'a str,
        settled: bool,
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct NounsInfoFE {
        id: String,
        amount: String,
        settled: bool,
        signature: Vec<u8>,
    }

    pub fn extract_nouns_info(body: &[u8]) -> Result<(), Error> {
        let (data, _): (Data, usize) = serde_json_core::from_slice(body).unwrap();
        let nouns_info = data.data.auctions[0].clone();
        Ok(())
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
        fn can_parse_nouns_response() {
            let response = r#"{
                "data": {
                    "auctions": [{
                        "amount": "81600000000000000000",
                        "id": "335",
                        "settled": false
                    }]
                }
            }"#;
            let result = extract_nouns_info(response.as_bytes());

            assert_eq!(result, Ok(()));
        }
    }
}
