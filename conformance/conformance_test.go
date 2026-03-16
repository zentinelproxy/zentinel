// Package conformance runs the official Gateway API conformance test suite
// against the Zentinel gateway controller.
//
// Run:
//
//	go test ./... -run TestConformance -gateway-class=zentinel -v -timeout=30m
//
// Generate report:
//
//	go test ./... -run TestConformance -gateway-class=zentinel \
//	  -report-output=reports/standard-v0.6.1-default-report.yaml -v -timeout=30m
package conformance

import (
	"testing"

	confv1 "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)

	if opts.GatewayClassName == "" {
		opts.GatewayClassName = "zentinel"
	}

	opts.ConformanceProfiles.Insert(suite.GatewayHTTPConformanceProfileName)

	// Declare core Gateway HTTP features. We set exactly the features required
	// by the GATEWAY-HTTP profile's core set so the suite can run.
	opts.SupportedFeatures = suite.FeaturesSet{}
	opts.SupportedFeatures.Insert(
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportReferenceGrant,
	)

	opts.Implementation = confv1.Implementation{
		Organization: "zentinelproxy",
		Project:      "zentinel",
		URL:          "https://github.com/zentinelproxy/zentinel",
		Version:      "0.6.1",
		Contact:      []string{"@zentinelproxy"},
	}

	conformance.RunConformanceWithOptions(t, opts)
}
