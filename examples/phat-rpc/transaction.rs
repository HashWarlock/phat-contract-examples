use crate::era::Era;
use ink_env::AccountId;
use ink_prelude::{string::String, vec::Vec};
use scale::{Compact, Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct UnsignedExtrinsic<Call> {
    pub pallet_id: u8,
    pub call_id: u8,
    pub call: Call,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct Remark {
    pub remark: Vec<u8>,
}

// #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
// #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
// struct Transfer {
//     dest: MultiAddress<AccountId, u32>,
//     currency_id: CurrencyId,
//     amount: Compact<u128>,
// }

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

/// A signature (a 512-bit value).
#[derive(Encode, Decode, Clone, Debug, scale_info::TypeInfo, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Hash))]
pub struct Signature(pub [u8; 64]);

impl TryFrom<&[u8]> for Signature {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() == 64 {
            let mut inner = [0u8; 64];
            inner.copy_from_slice(data);
            Ok(Signature(inner))
        } else {
            Err(())
        }
    }
}

#[derive(Encode, Decode, PartialEq, Eq, Clone, Debug, scale_info::TypeInfo)]
#[cfg_attr(feature = "std", derive(Hash))]
pub enum MultiSignature {
    /// An Ed25519 signature.
    Ed25519(Signature),
    /// An Sr25519 signature.
    Sr25519(Signature),
    /// An ECDSA/SECP256k1 signature.
    Ecdsa(Signature),
}
