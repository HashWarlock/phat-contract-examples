// This is an example of building a game of Roshambo (Rock, Paper, Scissors) in a Fat Contract.
//
//! Roshambo Fat Contract

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
use ink_lang as ink;

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod roshambo {
    use super::pink;
    use alloc::vec::Vec as StorageVec;
    use ink_env::{
        call::{build_call, utils::ReturnType, ExecutionInput, Selector},
        transfer,
    };
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use pink::PinkEnvironment;
    use scale::{Decode, Encode};

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    /// Error types
    pub enum Error {
        Error,
    }

    /// Auction statuses
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
    pub enum Move {
        /// Rock Move
        Rock,
        /// Paper Move
        Paper,
        /// Scissors Move
        Scissors,
        /// None is the default move
        None,
    }

    impl Move {
        pub fn from_u8(value: u8) -> Move {
            match value {
                1 => Move::Rock,
                2 => Move::Paper,
                3 => Move::Scissors,
                _ => Move::None,
            }
        }
    }

    /// Game Results
    #[derive(scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum GameResults {
        /// Player 1 is the winner
        Player1Wins,
        /// Player 2 is the winner
        Player2Wins,
        /// Match ends in a draw
        Draw,
    }

    /// Event emitted when a Player registers.
    #[ink(event)]
    pub struct PlayerRegistered {
        game_id: u32,
        player: AccountId,
    }

    /// Event emitted when a game is configured.
    #[ink(event)]
    pub struct GameConfigured {
        game_id: u32,
        player1: AccountId,
        player2: AccountId,
    }

    /// Event emitted when game is settled and cleared.
    #[ink(event)]
    pub struct GameSettled {
        game_id: u32,
        winner: AccountId,
    }

    /// Defines the storage of the contract.
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    pub struct Roshambo {
        /// Roshambo game owner
        hand_czar: AccountId,
        /// Game ID
        game_id: u32,
        /// Start time of the game
        start_block: BlockNumber,
        /// Length of Blocks until the game times out.
        game_timeout: u64,
        /// Player 1
        player1: Option<AccountId>,
        /// Player 2
        player2: Option<AccountId>,
        /// Winner of the last game played   
        winner: Option<AccountId>,
        /// Player 1's most recent move
        player1_move: u8,
        /// Player 2's most recent move
        player2_move: u8,
        /// Game results = storage of winners per game id
        game_results: Mapping<u32, Option<AccountId>>,
        /// Game status
        game_settled: bool,
    }

    impl Roshambo {
        /// Auction constructor.  
        /// Initializes the start_block to next block (if not set).  
        /// If start_block is set, checks it is in the future (to prevent backdating).  
        #[ink(constructor)]
        pub fn new() -> Self {
            let now = Self::env().block_number();
            let start_in = now + 1;
            // This call is required in order to correctly initialize the
            // `Mapping`s of our contract.
            ink_lang::codegen::initialize_contract(|contract: &mut Self| {
                contract.hand_czar = Self::env().caller();
                contract.game_id = 0;
                contract.start_block = start_in;
                contract.game_timeout = 0;
                contract.player1 = None;
                contract.player2 = None;
                contract.player1_move = 0;
                contract.player2_move = 0;
                contract.winner = None;
                contract.game_settled = true;
            })
        }

        /// Game results.
        #[ink(message)]
        pub fn results(&self, game_id: u32) -> Option<AccountId> {
            self.game_results.get(&game_id).unwrap_or(None)
        }
    }
}
