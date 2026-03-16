//! Reconcilers for Gateway API resources.
//!
//! Each reconciler watches a specific Gateway API resource type and
//! triggers config translation when resources change.

// TODO: Re-enable when BackendTLSPolicy CRD is available in gateway-api 0.20+
// pub mod backend_tls;
pub mod gateway;
pub mod gateway_class;
pub mod grpcroute;
pub mod httproute;
pub mod ingress;
pub mod reference_grant;
pub mod tcproute;
pub mod tlsroute;

// TODO: Re-enable when BackendTLSPolicy CRD is available in gateway-api 0.20+
// pub use backend_tls::BackendTlsPolicyReconciler;
pub use gateway::GatewayReconciler;
pub use gateway_class::GatewayClassReconciler;
pub use grpcroute::GrpcRouteReconciler;
pub use httproute::HttpRouteReconciler;
pub use ingress::IngressReconciler;
pub use reference_grant::ReferenceGrantIndex;
pub use tcproute::TcpRouteReconciler;
pub use tlsroute::TlsRouteReconciler;
