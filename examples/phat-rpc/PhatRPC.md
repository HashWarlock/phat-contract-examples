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

## Psuedo-Code Implementation
Example mimics the process used for subxt `create_signed` function.
```rust
#[ink(message)]
fn send_transaction(
    &self,
    chain: String,
    account_nonce: NextNonceOk,
    runtime_version: RuntimeVersionOk,
    genesis_hash: GenesisHashOk,
    call_data: Vec<u8>, // [pallet_index: u8, method_index: u8, call_params: Vec<u8>]
    extra: Extra, // (sp_runtime::generic::Era, Compact(nonce), Tip)
) -> Result<(), Vec<u8>> {
    if self.admin != self.env().caller() {
      return Err(Error::NoPermissions.encode());
    }
    let account_id = match self.chain_account_id.get(&chain) {
      Some(account_id) => account_id,
      None => return Err(Error::ChainNotConfigured.encode()),
    };
    let signer = match self.account_private.get(&chain) {
      Some(signer) => signer,
      None => return Err(Error::ChainNotConfigured.encode()),
    };
    let rpc_node = match self.rpc_nodes.get(&chain) {
      Some(rpc_node) => rpc_node,
      None => return Err(Error::ChainNotConfigured.encode()),
    };
    // SCALE encode call data to bytes (pallet u8, call u8, call params).
    let call_data_enc = Encoded(call_data);
    // Construct our custom additional params.
    let additional_params = (
        runtime_version.spec_version,
        runtime_version.transaction_version,
        genesis_hash.genesis_hash,
        // This should be configurable tx has a lifetime
        genesis_hash.genesis_hash,
    );
    // Construct signature
    let signature = {
        let mut bytes = Vec::new();
        call_data_enc.encode_to(&mut bytes);
        extra.encode_to(&mut bytes);
        additional_params.encode_to(&mut bytes);
        if bytes.len() > 256 {
            signer.sign(&sp_core::blake2_256(&bytes))
        } else {
            signer.sign(&bytes)
        }
    };
    // Encode Extrinsic
    let extrinsic = {
        let mut encoded_inner = Vec::new();
        // "is signed" + tx protocol v4
      (0b10000000 + 4u8).encode_to(&mut encoded_inner);
      // from address for signature
      account_id.encode_to(&mut encoded_inner);
      // the signature bytes
      signature.encode_to(&mut encoded_inner);
      // attach custom extra params
      extra.encode_to(&mut encoded_inner);
      // and now, call data
      call_data.encode_to(&mut encoded_inner);
      // now, prefix byte length:
      let len = Compact(
        u32::try_from(encoded_inner.len())
                .expect("extrinsic size expected to be <4GB"),
      );
      let mut encoded = Vec::new();
      len.encode_to(&mut encoded);
      encoded.extend(encoded_inner);
      encoded
    };
    // Encode extrinsic then send RPC Call
    let extrinsic_enc = Encoded(extrinsic);
    let data = format!(
      r#"{{"id":1,"jsonrpc":"2.0","method":"author_submitExtrinsic","params":["{}"]}}"#,
      extrinsic_enc
    ).into_bytes();
    let content_length = format!("{}", data.len());
    let headers: Vec<(String, String)> = vec![
      ("Content-Type".into(), "application/json".into()),
      ("Content-Length".into(), content_length),
    ];
    // Get next nonce for the account through HTTP request
    let response = http_post!(rpc_node, data, headers);
    if response.status_code != 200 {
      return Err(Error::RequestFailed.encode());
    }
    // May need a check or a similar submit and subscribe to validate function
    Ok(())
}
```