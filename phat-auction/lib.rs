#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod phat_auction {
    use super::pink;
    use alloc::{
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use pink::{http_get, http_post, PinkEnvironment};
    use scale::{Decode, Encode};
    use serde::Deserialize;
    use serde_json::json;

    /// RMRK NFT structure
    #[derive(Deserialize, Debug, Eq, PartialEq)]
    pub struct RmrkNft {
        id: String,
        metadata: String,
        image: String,
        rootowner: String,
    }

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    pub struct PhatAuction {
        /// Admin of the Auctions
        admin: AccountId,
        /// Token id
        token_id: String,
        /// Top bidder
        top_bidder: AccountId,
        /// Results from auctions
        auction_results: Mapping<String, u128>,
        /// The minimum price accepted in an auction
        reserve_price: u128,
        /// The minimum percentage increase between bids
        bid_increment: u128,
        /// Auction is settled bool
        settled: bool,
        /// Chat id
        chat_id: String,
        /// Bot id
        bot_id: String,
    }

    #[ink(event)]
    pub struct AuctionCreated {
        owner: AccountId,
        token_id: String,
    }

    #[ink(event)]
    pub struct AuctionBid {
        token_id: String,
        amount: u128,
        //extended: bool,
    }

    #[ink(event)]
    pub struct AuctionSettled {
        token_id: String,
        winner: AccountId,
        amount: u128,
    }

    #[ink(event)]
    pub struct AuctionSettingsUpdated {
        reserve_price: Balance,
        bid_increment: u128,
    }

    #[ink(event)]
    pub struct AuctionBotUpdated {
        updated: bool,
    }

    #[ink(event)]
    pub struct SetNewOwner {
        old_owner: AccountId,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        NotOwner,
        NotApproved,
        HttpError,
        OwnerCannotBidOnToken,
        TokenNotForAuction,
        TokenAuctionExpired,
        TokenAuctionNotFound,
        TokenValidationFailed,
        BidBelowReservePrice,
        BidBelowBidIncrement,
        TokenAuctionHasNotStarted,
        TokenAuctionInProgress,
        AlreadyTopBid,
        TokenAuctionResultsAlreadySet,
        NoWinner,
    }

    impl PhatAuction {
        #[ink(constructor)]
        pub fn default() -> Self {
            // Save sender as the contract admin
            let admin = Self::env().caller();

            // This call is required in order to correctly initialize the
            // `Mapping`s of our contract.
            ink_lang::codegen::initialize_contract(|contract: &mut Self| {
                contract.admin = admin;
                contract.top_bidder = admin;
                contract.token_id = Default::default();
                contract.reserve_price = 0u128;
                contract.bid_increment = 0u128;
                contract.settled = true;
                contract.chat_id = Default::default();
                contract.bot_id = Default::default();
            })
        }

        /// Set new owner of the contract
        #[ink(message)]
        pub fn set_owner(&mut self, new_owner: AccountId) -> Result<(), Error> {
            let sender = self.env().caller();
            if self.admin != sender {
                return Err(Error::NotOwner);
            }
            self.admin = new_owner;
            self.env().emit_event(SetNewOwner { old_owner: sender });

            Ok(())
        }

        /// Configure Auction Bot
        ///
        /// The admin must set up an auction bot that will relay the auction results to a private Telegram Group
        #[ink(message)]
        pub fn admin_set_auction_bot(
            &mut self,
            chat_id: String,
            bot_id: String,
        ) -> Result<(), Error> {
            // Hint: get the metadata about the contract through self.env()
            if self.env().caller() != self.admin {
                return Err(Error::NotOwner);
            }

            // Update chat id and bot id
            self.chat_id = chat_id;
            self.bot_id = bot_id;

            self.env().emit_event(AuctionBotUpdated { updated: true });

            Ok(())
        }

        /// Configure Auction Settings
        ///
        /// The admin must set the auction settings before deploying an auction
        #[ink(message)]
        pub fn admin_set_auction_settings(
            &mut self,
            token_id: String,
            reserve_price: Balance,
            bid_increment: u128,
        ) -> Result<(), Error> {
            // Hint: get the metadata about the contract through self.env()
            if self.env().caller() != self.admin {
                return Err(Error::NotOwner);
            }

            // Update auction configuration settings
            self.token_id = token_id;
            self.reserve_price = reserve_price.clone();
            self.bid_increment = bid_increment;
            self.settled = false;

            self.env().emit_event(AuctionSettingsUpdated {
                reserve_price,
                bid_increment,
            });

            Ok(())
        }

        /// Create an auction
        ///
        /// Only can be run by the admin and will interact with RMRK HTTP Endpoint to verify NFT information
        #[ink(message)]
        pub fn create_auction(&mut self, token_id: String) -> Result<(), Error> {
            let sender = self.env().caller();
            if sender != self.admin {
                return Err(Error::NotOwner);
            }
            if token_id != self.token_id {
                return Err(Error::TokenAuctionNotFound);
            }
            if !self.settled {
                return Err(Error::TokenAuctionInProgress);
            }
            // Verify RMRK NFT ID
            let api_url = "https://kanaria.rmrk.app/api/rmrk2/nft/".to_string();
            let api_url = format!("{}{}", api_url, token_id);
            let rmrk_nft: RmrkNft = self
                ._verify_token_id(token_id.clone(), api_url)
                .or(Err(Error::TokenValidationFailed))?;
            let text = format!(
                "***AUCTION ALERT***\nRMRK NFT ID: {}\nMetadata: {}\nImage URL: {}\nOwner: {}\n Reserve Price: {}\n",
                rmrk_nft.id, rmrk_nft.metadata, rmrk_nft.image, rmrk_nft.rootowner, self.reserve_price
            );
            let encoded: Vec<u8> =
                format!(r#"{{"chat_id":"{}","text":"{}"}}"#, self.chat_id, text).into_bytes();
            let content_length = format!("{}", encoded.len());
            let headers = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];
            let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_id);
            // Update Telegram Group
            let response = http_post!(tg_url, encoded, headers);
            if response.status_code != 200 {
                return Err(Error::HttpError);
            }

            self.env().emit_event(AuctionCreated {
                owner: sender,
                token_id,
            });

            Ok(())
        }

        /// Sender bids on an RMRK NFT Auction at the auto-increase bid
        #[ink(message)]
        pub fn send_bid(&mut self, amount: u128) -> Result<(), Error> {
            let sender = self.env().caller();
            if self.admin == sender {
                return Err(Error::OwnerCannotBidOnToken);
            }
            if !self.settled {
                return Err(Error::TokenAuctionInProgress);
            }
            if self.reserve_price == amount && self.top_bidder == sender {
                return Err(Error::AlreadyTopBid);
            }
            if self.reserve_price > amount {
                return Err(Error::BidBelowReservePrice);
            }
            self.reserve_price = amount;
            self.top_bidder = sender;

            self.env().emit_event(AuctionBid {
                token_id: self.token_id.clone(),
                amount: self.reserve_price,
            });

            Ok(())
        }

        #[ink(message)]
        pub fn update_new_bid(&self) -> Result<(), Error> {
            // Update TG channel
            let text = format!(
                "***NEW BID ALERT***\nRMRK NFT ID: {}\nNEW TOP BID: {} KSM\n",
                self.token_id, self.reserve_price
            );
            let encoded: Vec<u8> =
                format!(r#"{{"chat_id":"{}","text":"{}"}}"#, self.chat_id, text).into_bytes();
            let content_length = format!("{}", encoded.len());
            let headers = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];
            let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_id);
            // Update Telegram Group
            let response = http_post!(tg_url, encoded, headers);
            if response.status_code != 200 {
                return Err(Error::HttpError);
            }

            Ok(())
        }

        #[ink(message)]
        pub fn settle_auction(&mut self) -> Result<(), Error> {
            let sender = self.env().caller();
            if sender != self.admin {
                return Err(Error::NotOwner);
            }
            if sender == self.admin {
                return Err(Error::NoWinner);
            }
            // Update contract state
            self.settled = true;
            self._set_results(self.token_id.clone(), self.reserve_price);

            Ok(())
        }

        /// Update group of the results
        #[ink(message)]
        pub fn update_results(&self) -> Result<(), Error> {
            if !self.settled {
                return Err(Error::TokenAuctionInProgress);
            }

            // Update TG channel
            let text = format!(
                "***AUCTION HAS BEEN SETTLED ALERT***\nRMRK NFT ID: {}\nWinning Bidder: {:?}\nWinning Bid: {} KSM",
                self.token_id, self.top_bidder, self.reserve_price
            );
            let encoded: Vec<u8> =
                format!(r#"{{"chat_id":"{}","text":"{}"}}"#, self.chat_id, text).into_bytes();
            let content_length = format!("{}", encoded.len());
            let headers = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];
            let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_id);
            // Update Telegram Group
            let response = http_post!(tg_url, encoded, headers);
            if response.status_code != 200 {
                return Err(Error::HttpError);
            }

            self.env().emit_event(AuctionSettled {
                token_id: self.token_id.clone(),
                winner: self.top_bidder,
                amount: self.reserve_price,
            });

            Ok(())
        }

        /// Get the current top bid
        #[ink(message)]
        pub fn get_token_id(&self) -> String {
            self.token_id.clone()
        }

        /// Get the current top bid
        #[ink(message)]
        pub fn get_top_bid(&self) -> u128 {
            self.reserve_price
        }

        /// Get Auction status
        #[ink(message)]
        pub fn get_auction_status(&self) -> bool {
            self.settled
        }

        // Internal functions
        fn _verify_token_id(&self, token_id: String, api_url: String) -> Result<RmrkNft, Error> {
            let response = http_get!(api_url);
            if response.status_code != 200 {
                return Err(Error::TokenValidationFailed);
            }

            let body = response.body;
            let json_body = json!(body);
            let rmrk_nft: RmrkNft =
                serde_json::from_value(json_body).or(Err(Error::TokenValidationFailed))?;
            // Verify the NFT
            if token_id != rmrk_nft.id {
                return Err(Error::TokenValidationFailed);
            }

            Ok(rmrk_nft)
        }

        fn _set_results(&mut self, token_id: String, amount: u128) -> Result<(), Error> {
            let sender = self.env().caller();
            if self.auction_results.get(&token_id).is_some() {
                return Err(Error::TokenAuctionResultsAlreadySet);
            }
            self.auction_results.insert(&token_id, &amount);
            Ok(())
        }
    }
}
