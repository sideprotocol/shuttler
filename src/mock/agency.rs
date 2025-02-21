use side_proto::side::lending::{query_server::Query as LendingQuery, QueryCollateralAddressRequest, QueryCollateralAddressResponse, QueryLiquidationCetRequest, QueryLiquidationCetResponse, QueryLiquidationEventRequest, QueryLiquidationEventResponse, QueryLoanDlcMetaRequest, QueryLoanDlcMetaResponse, QueryLoanRequest, QueryLoanResponse, QueryLoansRequest, QueryLoansResponse, QueryParamsRequest, QueryParamsResponse, QueryRepaymentRequest, QueryRepaymentResponse};

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
    fn liquidation_cet<'life0,'async_trait>(&'life0 self,_request:tonic::Request<QueryLiquidationCetRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryLiquidationCetResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
    
    #[must_use]
    #[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
    fn loan<'life0,'async_trait>(&'life0 self,_request:tonic::Request<QueryLoanRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryLoanResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
    
    #[must_use]
    #[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
    fn loans<'life0,'async_trait>(&'life0 self,_request:tonic::Request<QueryLoansRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryLoansResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
    
    #[must_use]
    #[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
    fn loan_dlc_meta<'life0,'async_trait>(&'life0 self,_request:tonic::Request<QueryLoanDlcMetaRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryLoanDlcMetaResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
    
    #[must_use]
    #[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
    fn repayment<'life0,'async_trait>(&'life0 self,_request:tonic::Request<QueryRepaymentRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<QueryRepaymentResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

}