// @generated
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DelegateCallback {
    #[prost(string, tag = "1")]
    pub host_chain_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UndelegateCallback {
    #[prost(string, tag = "1")]
    pub host_chain_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferCallback {
    #[prost(uint64, tag = "1")]
    pub deposit_record_id: u64,
}
/// Params defines the parameters for the module.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    #[prost(string, tag = "1")]
    pub admin: ::prost::alloc::string::String,
}
/// GenesisState defines the yield module's genesis state.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(message, optional, tag = "1")]
    pub params: ::core::option::Option<Params>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HostChain {
    #[prost(string, tag = "1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub bech32prefix: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub connection_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub transfer_channel_id: ::prost::alloc::string::String,
    /// ibc denom on side
    #[prost(string, tag = "5")]
    pub ibc_denom: ::prost::alloc::string::String,
    /// native denom on host zone
    #[prost(string, tag = "6")]
    pub host_denom: ::prost::alloc::string::String,
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
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgRegisterHostChain {
    #[prost(string, tag = "1")]
    pub connection_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub bech32prefix: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub host_denom: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub ibc_denom: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub creator: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub transfer_channel_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgRegisterHostChainResponse {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DepositRecord {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(string, tag = "2")]
    pub amount: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub denom: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub host_chain_id: ::prost::alloc::string::String,
    #[prost(string, tag = "9")]
    pub receiver: ::prost::alloc::string::String,
    #[prost(enumeration = "deposit_record::Status", tag = "6")]
    pub status: i32,
    #[prost(uint64, tag = "7")]
    pub deposit_epoch_number: u64,
    #[prost(enumeration = "deposit_record::Source", tag = "8")]
    pub source: i32,
}
/// Nested message and enum types in `DepositRecord`.
pub mod deposit_record {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Status {
        /// in transfer queue to be sent to the delegation ICA (Hub)
        TransferFirstQueue = 0,
        /// transfer in progress (IBC packet sent, ack not received) (to Hub)
        TransferFirstInProgress = 2,
        /// in transfer queue to be sent to the delegation ICA (Stride)
        TransferSecondQueue = 3,
        /// transfer in progress (IBC packet sent, ack not received) (from Hub to stride)
        TransferSecondInProgress = 4,
        /// in staking queue on delegation ICA
        DelegationQueue = 1,
        /// staking in progress (ICA packet sent, ack not received)
        DelegationInProgress = 5,
    }
    impl Status {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Status::TransferFirstQueue => "TRANSFER_FIRST_QUEUE",
                Status::TransferFirstInProgress => "TRANSFER_FIRST_IN_PROGRESS",
                Status::TransferSecondQueue => "TRANSFER_SECOND_QUEUE",
                Status::TransferSecondInProgress => "TRANSFER_SECOND_IN_PROGRESS",
                Status::DelegationQueue => "DELEGATION_QUEUE",
                Status::DelegationInProgress => "DELEGATION_IN_PROGRESS",
            }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Source {
        Side = 0,
        Hub = 1,
    }
    impl Source {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Source::Side => "SIDE",
                Source::Hub => "HUB",
            }
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgLiquidStake {
    #[prost(string, tag = "1")]
    pub creator: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub denom: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub amount: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgLiquidStakeResponse {
    #[prost(int32, tag = "1")]
    pub id: i32,
}
include!("side.yield.tonic.rs");
// @@protoc_insertion_point(module)
