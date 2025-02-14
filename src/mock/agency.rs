use side_proto::side::lending::{query_server::Query as LendingQuery, QueryCollateralAddressRequest, QueryCollateralAddressResponse, QueryLiquidationEventRequest, QueryLiquidationEventResponse, QueryLoanCetRequest, QueryLoanCetResponse, QueryParamsRequest, QueryParamsResponse, QueryRepaymentTxRequest, QueryRepaymentTxResponse};

use super::MockQuery;

impl LendingQuery for MockQuery {
    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn params<'life0,'async_trait>(&'life0 self,_request:tonic::Request<QueryParamsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryParamsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn collateral_address<'life0,'async_trait>(&'life0 self,_request:tonic::Request<QueryCollateralAddressRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryCollateralAddressResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn liquidation_event<'life0,'async_trait>(&'life0 self,_request:tonic::Request<QueryLiquidationEventRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryLiquidationEventResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn loan_cet<'life0,'async_trait>(&'life0 self, _request:tonic::Request<QueryLoanCetRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryLoanCetResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn unsigned_payment_tx<'life0,'async_trait>(&'life0 self, _request:tonic::Request<QueryRepaymentTxRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryRepaymentTxResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
}