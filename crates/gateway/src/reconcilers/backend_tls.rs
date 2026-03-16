// TODO: Re-enable when BackendTLSPolicy CRD is available in gateway-api 0.20+
//
// BackendTLSPolicy was removed from the gateway-api crate in 0.20.0.
// This reconciler is temporarily disabled until the CRD is re-added
// or an alternative approach is implemented.
//
// Original implementation watched BackendTLSPolicy resources that define
// TLS validation requirements for backend connections.
