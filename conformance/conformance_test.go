// Package conformance runs the official Gateway API conformance test suite
// against the Zentinel gateway controller.
//
// Run with:
//
//	go test ./... -run TestConformance \
//	  -gateway-class=zentinel \
//	  -supported-features=HTTPRoute,ReferenceGrant \
//	  -v
package conformance

import (
	"testing"

	"sigs.k8s.io/gateway-api/conformance"
)

func TestConformance(t *testing.T) {
	conformance.RunConformance(t)
}
