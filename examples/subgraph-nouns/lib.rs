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
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use pink::{
        chain_extension::SigType, derive_sr25519_key, get_public_key, http_get, sign, verify,
        PinkEnvironment,
    };
    use scale::{Decode, Encode};

    #[ink(storage)]
    #[derive(Default)]
    pub struct NounsSubgraph {
        admin: AccountId,
        attestation_privkey: Vec<u8>,
        attestation_pubkey: Vec<u8>,
        nouns_id: u32,
        current_bid: u128,
        acceptable_price: u128,
        nouns_endpoint: String,
        nouns_post_data: String,
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct NounsInfo {
        id: u32,
        amount: u128,
        settled: AccountId,
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedNounsInfo {
        nouns_info: NounsInfo,
        signature: Vec<u8>,
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
            let nouns_endpoint =
                "https://api.thegraph.com/subgraphs/name/nounsdao/nouns-subgraph".to_string();
            let nouns_post_data = r#"{
                "query":"query MyQuery{
                    auctions(orderBy: endTime, orderDirection: desc, first: 1) {
                        id
                        amount
                        settled
                    }
                }","variables":null,"operationalName":"MyQuery"
            }"#;
            Self {
                admin,
                attestation_privkey: privkey,
                attestation_pubkey: pubkey,
                nouns_id: 0,
                current_bid: 0,
                acceptable_price: 0,
                nouns_endpoint,
                nouns_post_data,
            }
        }

        /// Set the acceptable price that the admin is comfortable bidding for a Noun.
        #[ink(message)]
        pub fn set_acceptable_price(&mut self, acceptable_price: u128) -> Result<(), Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            self.acceptable_price = acceptable_price;
            Ok(())
        }

        /// Set the last time admin queried for the latest Nouns bid price.
        #[ink(message)]
        pub fn set_nouns_info(&mut self, signed_nouns_info: SignedNounsInfo) -> Result<(), Error> {
            // Verify the Nouns Info
            let nouns_info = self.verify_nouns_info(signed_nouns_info)?;
            let nouns_id = nouns_info.id;
            let current_bid = nouns_info.amount;
            let settled = nouns_info.settled;
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

        /// Get the latest bid price on the current Noun up for auction. Sign the info & return the result.
        #[ink(message)]
        pub fn get_latest_nouns_info(&self) -> Result<SignedNounsInfo, Error> {
            // Get the latest nouns info through http_post
            let response = http_post!(self.nouns_endpoint, self.nouns_post_data)?;
            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }
            let body = response.body;
            // Extract Nouns Info
            let (nouns_info, _): (NounsInfo, usize) =
                serde_json_core::from_slice(body).or(Err(Error::InvalidBody))?;
            let result = self.sign_nouns_info(nouns_info);
            Ok(result)
        }

        /// Signs the `nouns_info` with the attestation key pair.
        pub fn sign_nouns_info(&self, nouns_info: NounsInfo) -> SignedNounsInfo {
            let encoded = Encode::encode(&nouns_info);
            let signature = sign!(&encoded, &self.attestation_privkey, SigType::Sr25519);
            SignedNounsInfo {
                nouns_info,
                signature,
            }
        }

        /// Verifies the signed nouns_info and return the inner data.
        pub fn verify_nouns_info(
            &self,
            signed_nouns_info: SignedNounsInfo,
        ) -> Result<NounsInfo, Error> {
            let encoded = Encode::encode(&signed_nouns_info.nouns_info);
            if !verify!(
                &encoded,
                &self.attestation_pubkey,
                &signed_nouns_info,
                SigType::Sr25519
            ) {
                return Err(Error::InvalidSignature);
            }
            Ok(signed_nouns_info.nouns_info)
        }
    }

    pub fn extract_nouns_info(body: &[u8]) -> Result<(NounsInfo), Error> {
        let (nouns_info, _): (NounsInfo, usize) =
            serde_json_core::from_slice(body).or(Err(Error::InvalidBody))?;
        println!("{:?}", nouns_info);

        Ok((nouns_info))
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
            let response = r#"{"data":{"auctions":[{"amount":"81600000000000000000","id":"335","settled":false}]}}"#;
            let result = extract_nouns_info(response.as_bytes())?;
            assert_eq!(
                result,
                Ok(NounsInfo {
                    id: 335,
                    amount: 81600000000000000000,
                    settled: false
                })
            );
        }

        #[ink::test]
        fn end_to_end() {
            //     use pink_extension::chain_extension::{mock, HttpResponse};
            //
            //     // Mock derive key call (a pregenerated key pair)
            //     mock::mock_derive_sr25519_key(|_| {
            //         hex::decode("78003ee90ff2544789399de83c60fa50b3b24ca86c7512d0680f64119207c80ab240b41344968b3e3a71a02c0e8b454658e00e9310f443935ecadbdd1674c683").unwrap()
            //     });
            //     mock::mock_get_public_key(|_| {
            //         hex::decode("ce786c340288b79a951c68f87da821d6c69abd1899dff695bda95e03f9c0b012")
            //             .unwrap()
            //     });
            //     mock::mock_sign(|_| b"mock-signature".to_vec());
            //     mock::mock_verify(|_| true);
            //
            //     // Test accounts
            //     let accounts = ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
            //         .expect("Cannot get accounts");
            //     // Construct a contract (deployed by `accounts.alice` by default)
            //     let mut contract = FatSample::default();
            //     assert_eq!(contract.admin, accounts.alice);
            //     // Admin (alice) can set POAP
            //     assert!(contract
            //         .admin_set_poap_code(vec!["code0".to_string(), "code1".to_string(),])
            //         .is_ok());
            //     // Generate an attestation
            //     //
            //     // Mock a http request first (the 256 bits account id is the pubkey of Alice)
            //     mock::mock_http_request(|_| {
            //         HttpResponse::ok(b"This gist is owned by address: 0x0101010101010101010101010101010101010101010101010101010101010101".to_vec())
            //     });
            //     let result = contract.attest_gist("https://gist.githubusercontent.com/h4x3rotab/0cabeb528bdaf30e4cf741e26b714e04/raw/620f958fb92baba585a77c1854d68dc986803b4e/test%2520gist".to_string());
            //     assert!(result.is_ok());
            //     let attestation = result.unwrap();
            //     assert_eq!(attestation.attestation.username, "h4x3rotab");
            //     assert_eq!(attestation.attestation.account_id, accounts.alice);
            //     // Before redeem
            //     assert_eq!(contract.my_poap(), None);
            //     // Redeem
            //     assert!(contract.redeem(attestation).is_ok());
            //     assert_eq!(contract.total_redeemed, 1);
            //     assert_eq!(
            //         contract.account_by_username.get("h4x3rotab".to_string()),
            //         Some(accounts.alice)
            //     );
            //     assert_eq!(
            //         contract.username_by_account.get(&accounts.alice),
            //         Some("h4x3rotab".to_string())
            //     );
            //     assert_eq!(contract.redeem_by_account.get(accounts.alice), Some(0));
            //     // Check my redemption code
            //     assert_eq!(contract.my_poap(), Some("code0".to_string()))
        }
    }
}
