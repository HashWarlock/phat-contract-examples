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
        GameInProgress,
        AlreadyChoseMove,
        BothPlayersChoseAMove,
        NoPermissions,
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
        /// Hand Czar is the winner
        HandCzarWins,
        /// Challenger is the winner
        ChallengerWins,
        /// Match ends in a draw
        Draw,
    }

    /// Event emitted when a Player registers.
    #[ink(event)]
    pub struct PlayerRegistered {
        game_id: u32,
        challenger: AccountId,
    }

    /// Event emitted when a game is configured.
    #[ink(event)]
    pub struct GameConfigured {
        game_id: u32,
        hand_czar: AccountId,
        challenger: AccountId,
    }

    /// Event emitted when player makes move
    #[ink(event)]
    pub struct PlayerMoved {
        game_id: u32,
        player: AccountId,
    }

    /// Challenger booted
    #[ink(event)]
    pub struct PlayerBooted {
        game_id: u32,
        challenger: AccountId,
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
        /// Challenger
        challenger: Option<AccountId>,
        /// Hand Czar most recent move
        hand_czar_move: u8,
        /// Challenger's most recent move
        challenger_move: u8,
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
                contract.challenger = None;
                contract.hand_czar_move = 0;
                contract.challenger_move = 0;
                contract.game_settled = true;
            })
        }

        /// Challenge the Hand Czar
        #[ink(message)]
        pub fn challenge_hand_czar(&mut self) -> Result<(), Error> {
            if self.challenger.is_some() {
                return Err(Error::GameInProgress);
            }
            // Set new challenger
            self.challenger = Some(self.env().caller());
            self.game_id += 1;
            self.game_settled = false;
            Ok(())
        }

        /// Rock, Paper, Scissors, Shoot!
        #[ink(message)]
        pub fn choose_a_move(&mut self, hand_move: u8) -> Result<(), Error> {
            let sender = self.env().caller();
            if self.challenger.is_some() && Some(sender) == self.challenger {
                if self.challenger_move > 0 {
                    return Err(Error::AlreadyChoseMove);
                }
                self.challenger_move = hand_move;
                self.env().emit_event(PlayerMoved {
                    game_id: self.game_id,
                    player: sender,
                });
                Ok(())
            } else if sender == self.hand_czar {
                if self.hand_czar_move > 0 {
                    return Err(Error::AlreadyChoseMove);
                }
                self.hand_czar_move = hand_move;
                self.env().emit_event(PlayerMoved {
                    game_id: self.game_id,
                    player: self.hand_czar,
                });
                Ok(())
            } else {
                return Err(Error::NoPermissions);
            }
        }

        /// Boot challenger for inactivity and clean slate
        #[ink(message)]
        pub fn boot_challenger(&mut self) -> Result<(), Error> {
            if self.hand_czar == self.env().caller() {
                if self.hand_czar_move > 0 && self.challenger_move > 0 {
                    return Err(Error::BothPlayersChoseAMove);
                }
                let winner: Option<AccountId> = None;
                self.challenger = None;
                self.hand_czar_move = 0;
                self.challenger_move = 0;
                self.game_settled = true;
                self.game_results.insert(&self.game_id, &winner);
            } else {
                return Err(Error::NoPermissions);
            }
            Ok(())
        }

        /// Settle game
        #[ink(message)]
        pub fn settle_game(&mut self) -> Result<(), Error> {
            if self.hand_czar == self.env().caller() {
                if self.hand_czar_move > 0 && self.challenger_move > 0 {
                    let winner = self.determine_winner();
                    self.challenger = None;
                    self.hand_czar_move = 0;
                    self.challenger_move = 0;
                    self.game_settled = true;
                    self.game_results.insert(&self.game_id, &winner);
                } else {
                    return Err(Error::GameInProgress);
                }
            } else {
                return Err(Error::NoPermissions);
            }
            Ok(())
        }

        /// Game results.
        #[ink(message)]
        pub fn results(&self, game_id: u32) -> Option<AccountId> {
            self.game_results.get(&game_id).unwrap_or(None)
        }

        /// Determine winner
        fn determine_winner(&self) -> Option<AccountId> {
            let hand_czar_move = Move::from_u8(self.hand_czar_move);
            let challenger_move = Move::from_u8(self.challenger_move);
            match hand_czar_move {
                Move::Rock => match challenger_move {
                    Move::Rock => None,
                    Move::Paper => self.challenger,
                    Move::Scissors => Some(self.hand_czar),
                    _ => None,
                },
                Move::Paper => match challenger_move {
                    Move::Rock => Some(self.hand_czar),
                    Move::Paper => None,
                    Move::Scissors => self.challenger,
                    _ => None,
                },
                Move::Scissors => match challenger_move {
                    Move::Rock => self.challenger,
                    Move::Paper => Some(self.hand_czar),
                    Move::Scissors => None,
                    _ => None,
                },
                _ => None,
            }
        }
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

        fn set_sender(sender: AccountId, amount: Balance) {
            ink_env::test::push_execution_context::<Environment>(
                sender,
                ink_env::account_id::<Environment>(),
                1000000,
                amount,
                ink_env::test::CallData::new(ink_env::call::Selector::new([0x00; 4])), /* dummy */
            );
        }

        #[ink::test]
        fn end_to_end() {
            use pink_extension::chain_extension::mock;
            // Mock derive key call (a pregenerated key pair)
            mock::mock_derive_sr25519_key(|_| {
                hex::decode("78003ee90ff2544789399de83c60fa50b3b24ca86c7512d0680f64119207c80ab240b41344968b3e3a71a02c0e8b454658e00e9310f443935ecadbdd1674c683").unwrap()
            });
            mock::mock_get_public_key(|_| {
                hex::decode("ce786c340288b79a951c68f87da821d6c69abd1899dff695bda95e03f9c0b012")
                    .unwrap()
            });

            // Test accounts
            let accounts = ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
                .expect("Cannot get accounts");
            mock::mock_sign(|_| b"mock-signature".to_vec());
            mock::mock_verify(|_| true);

            // Construct contract
            let mut contract = Roshambo::new();
            assert_eq!(contract.hand_czar, accounts.alice);
            let alice = accounts.alice;
            let bob = accounts.bob;
            contract.choose_a_move(1);
            set_sender(bob, 100);
            contract.challenge_hand_czar();
            contract.choose_a_move(2);
            set_sender(alice, 100);
            contract.settle_game();
            assert_eq!(contract.results(1), Some(bob));
        }
    }
}
