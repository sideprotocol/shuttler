use cosmos_sdk_proto::cosmos;

// @generated
/// Bitcoin Block Header
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHeader {
    #[prost(uint64, tag = "1")]
    pub version: u64,
    #[prost(string, tag = "2")]
    pub hash: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub height: u64,
    #[prost(string, tag = "4")]
    pub previous_block_hash: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub merkle_root: ::prost::alloc::string::String,
    #[prost(uint64, tag = "6")]
    pub nonce: u64,
    #[prost(string, tag = "7")]
    pub bits: ::prost::alloc::string::String,
    #[prost(uint64, tag = "8")]
    pub time: u64,
    #[prost(uint64, tag = "9")]
    pub ntx: u64,
}
/// Bitcoin Signing Request
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinSigningRequest {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub txid: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub psbt: ::prost::alloc::string::String,
    #[prost(enumeration = "SigningStatus", tag = "4")]
    pub status: i32,
    #[prost(uint64, tag = "5")]
    pub sequence: u64,
    /// The vault address that the request is associated with
    #[prost(string, tag = "6")]
    pub vault_address: ::prost::alloc::string::String,
}
/// Bitcoin UTXO
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Utxo {
    #[prost(string, tag = "1")]
    pub txid: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub vout: u64,
    #[prost(string, tag = "3")]
    pub address: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub amount: u64,
    /// height is used for calculating confirmations
    #[prost(uint64, tag = "5")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub pub_key_script: ::prost::alloc::vec::Vec<u8>,
    #[prost(bool, tag = "7")]
    pub is_coinbase: bool,
    #[prost(bool, tag = "8")]
    pub is_locked: bool,
}
/// Bitcoin Signing Status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SigningStatus {
    /// SIGNING_STATUS_UNSPECIFIED - Default value, should not be used
    Unspecified = 0,
    /// SIGNING_STATUS_CREATED - The signing request is created
    Created = 1,
    /// SIGNING_STATUS_SIGNED - The signing request is signed
    Signed = 2,
    /// SIGNING_STATUS_BROADCASTED - The signing request is broadcasted
    Broadcasted = 3,
    /// SIGNING_STATUS_CONFIRMED - The signing request is confirmed
    Confirmed = 4,
    /// SIGNING_STATUS_REJECTED - The signing request is rejected
    Rejected = 5,
}
impl SigningStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            SigningStatus::Unspecified => "SIGNING_STATUS_UNSPECIFIED",
            SigningStatus::Created => "SIGNING_STATUS_CREATED",
            SigningStatus::Signed => "SIGNING_STATUS_SIGNED",
            SigningStatus::Broadcasted => "SIGNING_STATUS_BROADCASTED",
            SigningStatus::Confirmed => "SIGNING_STATUS_CONFIRMED",
            SigningStatus::Rejected => "SIGNING_STATUS_REJECTED",
        }
    }
}
/// Params defines the parameters for the module.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    /// Only accept blocks sending from these addresses
    #[prost(string, repeated, tag = "1")]
    pub authorized_relayers: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// The minimum number of confirmations required for a block to be accepted
    #[prost(int32, tag = "2")]
    pub confirmations: i32,
    /// Indicates the maximum depth or distance from the latest block up to which transactions are considered for acceptance.
    #[prost(uint64, tag = "3")]
    pub max_acceptable_block_depth: u64,
    /// the denomanation of the voucher
    #[prost(string, tag = "4")]
    pub btc_voucher_denom: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "5")]
    pub vaults: ::prost::alloc::vec::Vec<Vault>,
}
/// Vault defines the parameters for the module.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Vault {
    /// the depositor should send their btc to this address
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
    /// the pub key to which the voucher is sent
    #[prost(string, tag = "2")]
    pub pub_key: ::prost::alloc::string::String,
    /// the address to which the voucher is sent
    #[prost(enumeration = "AssetType", tag = "4")]
    pub asset_type: i32,
}
/// AssetType defines the type of asset
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AssetType {
    /// Unspecified asset type
    Unspecified = 0,
    /// BTC
    Btc = 1,
    /// BRC20: ordi, sats
    Brc20 = 2,
    /// RUNE, dog*go*to*the*moon
    Rune = 3,
}
impl AssetType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AssetType::Unspecified => "ASSET_TYPE_UNSPECIFIED",
            AssetType::Btc => "ASSET_TYPE_BTC",
            AssetType::Brc20 => "ASSET_TYPE_BRC20",
            AssetType::Rune => "ASSET_TYPE_RUNE",
        }
    }
}
/// GenesisState defines the btc light client module's genesis state.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(message, optional, tag = "1")]
    pub params: ::core::option::Option<Params>,
    /// the chain tip of the bitcoin chain
    #[prost(message, optional, tag = "2")]
    pub best_block_header: ::core::option::Option<BlockHeader>,
    #[prost(message, repeated, tag = "3")]
    pub block_headers: ::prost::alloc::vec::Vec<BlockHeader>,
    #[prost(message, repeated, tag = "4")]
    pub utxos: ::prost::alloc::vec::Vec<Utxo>,
}
/// QuerySigningRequestRequest is request type for the Query/SigningRequest RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuerySigningRequestRequest {
    #[prost(enumeration = "SigningStatus", tag = "1")]
    pub status: i32,
    #[prost(message, optional, tag = "2")]
    pub pagination:
        ::core::option::Option<cosmos::base::query::v1beta1::PageResponse>,
}
/// QuerySigningRequestResponse is response type for the Query/SigningRequest RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuerySigningRequestResponse {
    #[prost(message, repeated, tag = "1")]
    pub requests: ::prost::alloc::vec::Vec<BitcoinSigningRequest>,
    #[prost(message, optional, tag = "2")]
    pub pagination:
        ::core::option::Option<cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryParamsRequest is request type for the Query/Params RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryParamsRequest {}
/// QueryParamsResponse is response type for the Query/Params RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryParamsResponse {
    /// params holds all the parameters of this module.
    #[prost(message, optional, tag = "1")]
    pub params: ::core::option::Option<Params>,
}
/// QueryChainTipRequest is request type for the Query/ChainTip RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryChainTipRequest {}
/// QueryChainTipResponse is response type for the Query/ChainTip RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryChainTipResponse {
    #[prost(string, tag = "1")]
    pub hash: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
}
/// QueryBlockHeaderByHeightRequest is the request type for the Query/BlockHeaderByHeight RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBlockHeaderByHeightRequest {
    #[prost(uint64, tag = "1")]
    pub height: u64,
}
/// QueryBlockHeaderByHeightResponse is the response type for the Query/BlockHeaderByHeight RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBlockHeaderByHeightResponse {
    #[prost(message, optional, tag = "1")]
    pub block_header: ::core::option::Option<BlockHeader>,
}
/// QueryBlockHeaderByHashRequest is the request type for the Query/BlockHeaderByHash RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBlockHeaderByHashRequest {
    #[prost(string, tag = "1")]
    pub hash: ::prost::alloc::string::String,
}
/// QueryBlockHeaderByHashResponse is the response type for the Query/BlockHeaderByHash RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBlockHeaderByHashResponse {
    #[prost(message, optional, tag = "1")]
    pub block_header: ::core::option::Option<BlockHeader>,
}
/// QueryUTXOsRequest is the request type for the Query/UTXOs RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryUtxOsRequest {}
/// QueryUTXOsResponse is the response type for the Query/UTXOs RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryUtxOsResponse {
    #[prost(message, repeated, tag = "1")]
    pub utxos: ::prost::alloc::vec::Vec<Utxo>,
}
/// QueryUTXOsByAddressRequest is the request type for the Query/UTXOsByAddress RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryUtxOsByAddressRequest {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
}
/// QueryUTXOsByAddressResponse is the response type for the Query/UTXOsByAddress RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryUtxOsByAddressResponse {
    #[prost(message, repeated, tag = "1")]
    pub utxos: ::prost::alloc::vec::Vec<Utxo>,
}
/// MsgSubmitWithdrawStatusRequest defines the Msg/SubmitWithdrawStatus request type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitWithdrawStatusRequest {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub txid: ::prost::alloc::string::String,
    #[prost(enumeration = "SigningStatus", tag = "3")]
    pub status: i32,
}
/// MsgSubmitWithdrawStatusResponse defines the Msg/SubmitWithdrawStatus response type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitWithdrawStatusResponse {}
/// MsgBlockHeaderRequest defines the Msg/SubmitBlockHeaders request type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitBlockHeaderRequest {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "2")]
    pub block_headers: ::prost::alloc::vec::Vec<BlockHeader>,
}
/// MsgSubmitBlockHeadersResponse defines the Msg/SubmitBlockHeaders response type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitBlockHeadersResponse {}
/// MsgSubmitTransactionRequest defines the Msg/SubmitTransaction request type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitDepositTransactionRequest {
    /// this is relayer address who submit the bitcoin transaction to the side chain
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub blockhash: ::prost::alloc::string::String,
    /// the tx bytes in base64 format
    /// used for parsing the sender of the transaction
    #[prost(string, tag = "3")]
    pub prev_tx_bytes: ::prost::alloc::string::String,
    /// the tx bytes in base64 format
    #[prost(string, tag = "4")]
    pub tx_bytes: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "5")]
    pub proof: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// MsgSubmitTransactionResponse defines the Msg/SubmitTransaction response type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitDepositTransactionResponse {}
/// MsgSubmitTransactionRequest defines the Msg/SubmitTransaction request type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitWithdrawTransactionRequest {
    /// this is relayer address who submit the bitcoin transaction to the side chain
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub blockhash: ::prost::alloc::string::String,
    /// the tx bytes in base64 format
    #[prost(string, tag = "4")]
    pub tx_bytes: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "5")]
    pub proof: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// MsgSubmitTransactionResponse defines the Msg/SubmitTransaction response type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitWithdrawTransactionResponse {}
/// Msg defines the MsgUpdateSender service.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateQualifiedRelayersRequest {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    /// update senders who can send block headers to the side chain
    #[prost(string, repeated, tag = "2")]
    pub relayers: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// MsgUpdateSenderResponse defines the Msg/UpdateSender response type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateQualifiedRelayersResponse {}
/// MsgWithdrawBitcoinRequest defines the Msg/WithdrawBitcoin request type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgWithdrawBitcoinRequest {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    /// withdraw amount in satoshi, etc: 100000000sat = 1btc
    #[prost(string, tag = "2")]
    pub amount: ::prost::alloc::string::String,
    /// fee rate in sats/vB
    #[prost(string, tag = "3")]
    pub fee_rate: ::prost::alloc::string::String,
}
/// MsgWithdrawBitcoinResponse defines the Msg/WithdrawBitcoin response type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgWithdrawBitcoinResponse {}
/// MsgSubmitWithdrawSignaturesRequest defines the Msg/SubmitWithdrawSignatures request type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitWithdrawSignaturesRequest {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub txid: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub psbt: ::prost::alloc::string::String,
}
/// MsgSubmitWithdrawSignaturesResponse defines the Msg/SubmitWithdrawSignatures response type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitWithdrawSignaturesResponse {}
include!("side.btcbridge.tonic.rs");
// @@protoc_insertion_point(module)
