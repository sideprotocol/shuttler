// @generated
/// Params defines the parameters for the module.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    #[prost(uint64, tag = "1")]
    pub pool_creation_fee: u64,
}
/// GenesisState defines the gmm module's genesis state.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(message, optional, tag = "1")]
    pub params: ::core::option::Option<Params>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolParams {
    #[prost(enumeration = "PoolType", tag = "1")]
    pub r#type: i32,
    /// swapFee is ranged from 0 to 10000.
    #[prost(string, tag = "2")]
    pub swap_fee: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub exit_fee: ::prost::alloc::string::String,
    #[prost(bool, tag = "4")]
    pub use_oracle: bool,
    /// Amplifier parameters for stable pool.
    #[prost(string, tag = "5")]
    pub amp: ::prost::alloc::string::String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PoolType {
    Weight = 0,
    Stable = 1,
}
impl PoolType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            PoolType::Weight => "WEIGHT",
            PoolType::Stable => "STABLE",
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolAsset {
    #[prost(message, optional, tag = "1")]
    pub token: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
    #[prost(string, tag = "2")]
    pub weight: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub decimal: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Pool {
    /// option (cosmos_proto.implements_interface) = "PoolI";
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub sender: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub pool_params: ::core::option::Option<PoolParams>,
    #[prost(message, repeated, tag = "4")]
    pub assets: ::prost::alloc::vec::Vec<PoolAsset>,
    /// sum of all LP tokens sent out
    #[prost(message, optional, tag = "5")]
    pub total_shares: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolI {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub source_creator: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub assets: ::prost::alloc::vec::Vec<PoolWasmAsset>,
    #[prost(uint32, tag = "4")]
    pub swap_fee: u32,
    #[prost(string, tag = "5")]
    pub amp: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "6")]
    pub supply: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
    #[prost(enumeration = "PoolType", tag = "7")]
    pub pool_type: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolWasmAsset {
    #[prost(message, optional, tag = "1")]
    pub balance: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
    #[prost(uint32, tag = "2")]
    pub weight: u32,
    #[prost(uint32, tag = "3")]
    pub decimal: u32,
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
/// QueryLiquidityPoolRequest is request type for the Query/Liquidity RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPoolRequest {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
}
/// QueryLiquidityPoolResponse is response type for the Query/Liquidity RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPoolResponse {
    #[prost(message, optional, tag = "1")]
    pub pool: ::core::option::Option<PoolI>,
}
/// QueryPoolsRequest is request type for the Query/Liquidities RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryAllPoolsRequest {
    #[prost(message, optional, tag = "2")]
    pub pagination: ::core::option::Option<super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryPoolsRequest is request type for the Query/Liquidities RPC method.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPoolsRequest {
    #[prost(string, tag = "1")]
    pub creator: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub pagination: ::core::option::Option<super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryPoolsResponse is response type for the Query/Pools RPC method
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPoolsResponse {
    #[prost(message, repeated, tag = "1")]
    pub pools: ::prost::alloc::vec::Vec<PoolI>,
    #[prost(message, optional, tag = "2")]
    pub pagination:
        ::core::option::Option<super::super::cosmos::base::query::v1beta1::PageResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryVolumeRequest {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryVolumeResponse {
    #[prost(message, repeated, tag = "1")]
    pub volumes: ::prost::alloc::vec::Vec<super::super::cosmos::base::v1beta1::Coin>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryTotalVolumeRequest {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryTotalVolumeResponse {
    #[prost(message, repeated, tag = "1")]
    pub volumes: ::prost::alloc::vec::Vec<super::super::cosmos::base::v1beta1::Coin>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryAprRequest {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryAprResponse {
    #[prost(message, repeated, tag = "1")]
    pub apr: ::prost::alloc::vec::Vec<super::super::cosmos::base::v1beta1::Coin>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreatePool {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub params: ::core::option::Option<PoolParams>,
    #[prost(message, repeated, tag = "3")]
    pub liquidity: ::prost::alloc::vec::Vec<PoolAsset>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreatePoolResponse {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAddLiquidity {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub pool_id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub liquidity: ::prost::alloc::vec::Vec<super::super::cosmos::base::v1beta1::Coin>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAddLiquidityResponse {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgWithdraw {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub receiver: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub pool_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub share: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgWithdrawResponse {
    #[prost(message, optional, tag = "1")]
    pub share: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSwap {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub pool_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub token_in: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
    #[prost(message, optional, tag = "4")]
    pub token_out: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
    #[prost(string, tag = "5")]
    pub slippage: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSwapResponse {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub token_in: ::core::option::Option<super::super::cosmos::base::v1beta1::Coin>,
}
include!("side.gmm.tonic.rs");
// @@protoc_insertion_point(module)
