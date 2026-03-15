// Package conformance runs the official Gateway API conformance test suite
// against the Zentinel gateway controller.
//
// Run:
//
//	go test ./... -run TestConformance -gateway-class=zentinel -v
//
// Generate report:
//
//	go test ./... -run TestConformance -gateway-class=zentinel \
//	  -report-output=reports/standard-v0.6.1-default-report.yaml -v
package conformance

import (
	"testing"

	confv1 "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)

	if opts.GatewayClassName == "" {
		opts.GatewayClassName = "zentinel"
	}

	opts.ConformanceProfiles.Insert(suite.GatewayHTTPConformanceProfileName)

	opts.Implementation = confv1.Implementation{
		Organization: "zentinelproxy",
		Project:      "zentinel",
		URL:          "https://github.com/zentinelproxy/zentinel",
		Version:      "0.6.1",
		Contact:      []string{"@zentinelproxy"},
	}

	conformance.RunConformanceWithOptions(t, opts)
}
