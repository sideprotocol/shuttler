// @generated
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Query {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub connection_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub query_type: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "5")]
    pub request_data: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "13")]
    pub callback_module: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub callback_id: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "12")]
    pub callback_data: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "TimeoutPolicy", tag = "15")]
    pub timeout_policy: i32,
    #[prost(message, optional, tag = "14")]
    pub timeout_duration: ::core::option::Option<::prost_types::Duration>,
    #[prost(uint64, tag = "9")]
    pub timeout_timestamp: u64,
    #[prost(bool, tag = "11")]
    pub request_sent: bool,
    #[prost(uint64, tag = "16")]
    pub submission_height: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DataPoint {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub remote_height: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub local_height: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "4")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// GenesisState defines the epochs module's genesis state.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(message, repeated, tag = "1")]
    pub queries: ::prost::alloc::vec::Vec<Query>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum TimeoutPolicy {
    RejectQueryResponse = 0,
    RetryQueryRequest = 1,
    ExecuteQueryCallback = 2,
}
impl TimeoutPolicy {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            TimeoutPolicy::RejectQueryResponse => "REJECT_QUERY_RESPONSE",
            TimeoutPolicy::RetryQueryRequest => "RETRY_QUERY_REQUEST",
            TimeoutPolicy::ExecuteQueryCallback => "EXECUTE_QUERY_CALLBACK",
        }
    }
}
/// MsgSubmitQueryResponse represents a message type to fulfil a query request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitQueryResponse {
    #[prost(string, tag = "1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub query_id: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "3")]
    pub result: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub proof_ops: ::core::option::Option<::tendermint_proto::v0_34::crypto::ProofOps>,
    #[prost(int64, tag = "5")]
    pub height: i64,
    #[prost(string, tag = "6")]
    pub from_address: ::prost::alloc::string::String,
}
/// MsgSubmitQueryResponseResponse defines the MsgSubmitQueryResponse response
/// type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSubmitQueryResponseResponse {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingQueriesRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryPendingQueriesResponse {
    #[prost(message, repeated, tag = "1")]
    pub pending_queries: ::prost::alloc::vec::Vec<Query>,
}
include!("side.interchainquery.v1.tonic.rs");
// @@protoc_insertion_point(module)
