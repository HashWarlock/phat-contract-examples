# Phat RPC

## Send a Remark to a Substrate Based Chain

Create an unsigned payload with the following information:
- `system_accountNextIndex`
    - `nonce` for account
- `state_getRuntimeVersion`
    - `runtime_version`
    - `transaction_version`
- `chain_getBlockHash`
    - `genesis_hash`
- `Call`
    - pallet index: `00`
    - call index: `08`
    - remark: `Phala was here :P`
- `Extra`
    - `sp_runtime::generic::Era`
    - `parity_scale_codec::Compact(pub_key_nonce)`
    - `parity_scale_codec::Compact(0u128)`
- `Additional`
    - `runtime_version.spec_version`
    - `runtime_version.transaction_version`
    - `genesis_hash`
    - `genesis_hash` **Note:** for immortal txs

Sign the unsigned payload with the derived public key in the Phat RPC contract:
- `Signature`

## Signed Transaction
![](../../static/Substrate-Transaction.png)