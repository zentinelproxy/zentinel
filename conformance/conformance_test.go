// Package conformance runs the official Gateway API conformance test suite
// against the Zentinel gateway controller.
//
// Run with:
//
//	go test ./... -run TestConformance \
//	  -gateway-class=zentinel \
//	  -controller-name=zentinelproxy.io/gateway-controller \
//	  -supported-features=HTTPRoute,ReferenceGrant \
//	  -v
package conformance

import (
	"testing"

	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)

	// Override defaults for Zentinel
	if opts.GatewayClassName == "" {
		opts.GatewayClassName = "zentinel"
	}
	if opts.ControllerName == "" {
		opts.ControllerName = "zentinelproxy.io/gateway-controller"
	}

	// Enable features we support
	opts.EnableAllSupportedFeatures = false
	opts.SupportedFeatures = suite.AllFeatures

	// Run the conformance suite
	conformance.RunConformanceWithOptions(t, opts)
}
