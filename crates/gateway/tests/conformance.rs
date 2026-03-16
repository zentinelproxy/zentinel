//! Gateway API conformance test harness.
//!
//! These tests validate that zentinel-gateway correctly implements the
//! Kubernetes Gateway API specification. They require a running Kubernetes
//! cluster with Gateway API CRDs installed.
//!
//! # Prerequisites
//!
//! ```bash
//! # Install Gateway API CRDs
//! kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.1/standard-install.yaml
//!
//! # Deploy zentinel-gateway controller
//! helm install zentinel-gateway deploy/helm/zentinel-gateway/
//! ```
//!
//! # Running
//!
//! ```bash
//! # Run conformance tests (requires cluster access)
//! cargo test -p zentinel-gateway --test conformance -- --ignored
//! ```
//!
//! # Official Conformance Suite
//!
//! The full Gateway API conformance suite is Go-based and should be run
//! separately. See `docs/conformance.md` for instructions.

use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::{Gateway, GatewaySpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, PostParams};
use kube::Client;

/// Helper to create a test GatewayClass.
async fn create_test_gateway_class(client: &Client, name: &str) -> GatewayClass {
    let api: Api<GatewayClass> = Api::all(client.clone());
    let gc = GatewayClass {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: gateway_api::gatewayclasses::GatewayClassSpec {
            controller_name: "zentinelproxy.io/gateway-controller".to_string(),
            description: Some("Test GatewayClass".to_string()),
            parameters_ref: None,
        },
        status: None,
    };
    api.create(&PostParams::default(), &gc)
        .await
        .expect("Failed to create GatewayClass")
}

/// Helper to clean up test resources.
async fn cleanup_gateway_class(client: &Client, name: &str) {
    let api: Api<GatewayClass> = Api::all(client.clone());
    let _ = api.delete(name, &DeleteParams::default()).await;
}

#[tokio::test]
#[ignore = "requires running Kubernetes cluster"]
async fn gateway_class_accepted_by_controller() {
    let client = Client::try_default()
        .await
        .expect("Failed to create Kubernetes client — is a cluster running?");

    let gc_name = "conformance-test-class";

    // Clean up from previous runs
    cleanup_gateway_class(&client, gc_name).await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Create GatewayClass
    let gc = create_test_gateway_class(&client, gc_name).await;
    assert_eq!(
        gc.spec.controller_name,
        "zentinelproxy.io/gateway-controller"
    );

    // Wait for controller to set Accepted condition
    let api: Api<GatewayClass> = Api::all(client.clone());
    let mut accepted = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Ok(gc) = api.get(gc_name).await {
            if let Some(ref status) = gc.status {
                if let Some(ref conditions) = status.conditions {
                    if conditions
                        .iter()
                        .any(|c| c.type_ == "Accepted" && c.status == "True")
                    {
                        accepted = true;
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    cleanup_gateway_class(&client, gc_name).await;

    assert!(accepted, "GatewayClass was not accepted within 30 seconds");
}

#[tokio::test]
#[ignore = "requires running Kubernetes cluster"]
async fn gateway_gets_programmed_status() {
    let client = Client::try_default()
        .await
        .expect("Failed to create Kubernetes client");

    let gc_name = "conformance-gw-test-class";
    let gw_name = "conformance-test-gateway";
    let ns = "default";

    // Setup
    cleanup_gateway_class(&client, gc_name).await;
    let gw_api: Api<Gateway> = Api::namespaced(client.clone(), ns);
    let _ = gw_api.delete(gw_name, &DeleteParams::default()).await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    create_test_gateway_class(&client, gc_name).await;

    // Create Gateway
    let gw = Gateway {
        metadata: ObjectMeta {
            name: Some(gw_name.to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: gc_name.to_string(),
            listeners: vec![gateway_api::gateways::GatewayListeners {
                name: "http".to_string(),
                port: 8080,
                protocol: "HTTP".to_string(),
                hostname: None,
                allowed_routes: None,
                tls: None,
            }],
            ..Default::default()
        },
        status: None,
    };
    gw_api
        .create(&PostParams::default(), &gw)
        .await
        .expect("Failed to create Gateway");

    // Wait for Programmed condition
    let mut programmed = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Ok(gw) = gw_api.get(gw_name).await {
            if let Some(ref status) = gw.status {
                if let Some(ref conditions) = status.conditions {
                    if conditions
                        .iter()
                        .any(|c| c.type_ == "Programmed" && c.status == "True")
                    {
                        programmed = true;
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    let _ = gw_api.delete(gw_name, &DeleteParams::default()).await;
    cleanup_gateway_class(&client, gc_name).await;

    assert!(programmed, "Gateway was not programmed within 30 seconds");
}
