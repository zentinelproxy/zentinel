//! Main controller that wires together all reconcilers and runs them.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use futures::StreamExt;
use gateway_api::experimental::tlsroutes::TLSRoute;
use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::Gateway;
use gateway_api::grpcroutes::GRPCRoute;
use gateway_api::httproutes::HTTPRoute;
use gateway_api::referencegrants::ReferenceGrant;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::api::core::v1::Secret;
use kube::api::ListParams;
use kube::runtime::controller::Controller;
use kube::runtime::watcher;
use kube::{Api, Client};
use tracing::{error, info, warn};

use zentinel_config::Config;

use crate::error::GatewayError;
use crate::reconcilers::{
    GatewayClassReconciler, GatewayReconciler, GrpcRouteReconciler, HttpRouteReconciler,
    IngressReconciler, ReferenceGrantIndex, TlsRouteReconciler,
};
use crate::config_writer::ConfigWriter;
use crate::tls::SecretCertificateManager;
use crate::translator::ConfigTranslator;

/// Default directory for writing TLS certificates extracted from Secrets.
const DEFAULT_CERT_DIR: &str = "/tmp/zentinel-gateway-certs";

/// The main Gateway API controller.
///
/// Runs reconciliation loops for GatewayClass, Gateway, HTTPRoute, and
/// ReferenceGrant resources. Produces a `zentinel_config::Config` that
/// the proxy data plane can consume.
pub struct GatewayController {
    client: Client,
    config: Arc<ArcSwap<Config>>,
    reference_grants: Arc<ReferenceGrantIndex>,
    cert_manager: Arc<SecretCertificateManager>,
    config_output_path: Option<PathBuf>,
}

impl GatewayController {
    /// Create a new controller.
    pub async fn new() -> Result<Self, GatewayError> {
        let client = Client::try_default().await?;
        let config = Arc::new(ArcSwap::from_pointee(Config::default_for_testing()));
        let reference_grants = Arc::new(ReferenceGrantIndex::new());

        let cert_dir = PathBuf::from(DEFAULT_CERT_DIR);
        std::fs::create_dir_all(&cert_dir).map_err(|e| {
            GatewayError::Translation(format!(
                "Failed to create certificate directory {}: {e}",
                cert_dir.display()
            ))
        })?;
        let cert_manager = Arc::new(SecretCertificateManager::new(client.clone(), cert_dir));

        Ok(Self {
            client,
            config,
            reference_grants,
            cert_manager,
            config_output_path: None,
        })
    }

    /// Create a controller with a pre-existing config store (for integration
    /// with an existing Zentinel proxy instance).
    pub fn with_config(client: Client, config: Arc<ArcSwap<Config>>) -> Self {
        let reference_grants = Arc::new(ReferenceGrantIndex::new());
        let cert_dir = PathBuf::from(DEFAULT_CERT_DIR);
        let _ = std::fs::create_dir_all(&cert_dir);
        let cert_manager = Arc::new(SecretCertificateManager::new(client.clone(), cert_dir));

        Self {
            client,
            config,
            reference_grants,
            cert_manager,
            config_output_path: None,
        }
    }

    /// Set the output path for writing translated config as KDL.
    ///
    /// When set, the controller writes a KDL config file after each
    /// reconciliation cycle. A Zentinel proxy sidecar reads this file
    /// with `auto-reload: true` to serve traffic.
    pub fn with_config_output(mut self, path: PathBuf) -> Self {
        self.config_output_path = Some(path);
        self
    }

    /// Get a handle to the shared config (for the data plane to read).
    pub fn config_handle(&self) -> Arc<ArcSwap<Config>> {
        Arc::clone(&self.config)
    }

    /// Run all reconciliation loops until shutdown.
    ///
    /// This spawns separate tasks for each resource type and waits for
    /// all of them. Cancellation is handled via tokio's cooperative
    /// cancellation (dropping the future).
    pub async fn run(self) -> Result<(), GatewayError> {
        let mut translator = ConfigTranslator::new(
            Arc::clone(&self.config),
            Arc::clone(&self.reference_grants),
            Arc::clone(&self.cert_manager),
        );

        if let Some(ref path) = self.config_output_path {
            translator = translator.with_config_writer(ConfigWriter::new(path.clone()));
            info!(path = %path.display(), "Config output enabled for proxy sidecar");
        }

        let translator = Arc::new(translator);

        info!("Starting Gateway API controller");

        // Build initial ReferenceGrant index
        self.rebuild_reference_grants().await?;

        // Run all controllers concurrently
        let gateway_class_fut = self.run_gateway_class_controller();
        let gateway_fut = self.run_gateway_controller();
        let httproute_fut = self.run_httproute_controller(Arc::clone(&translator));
        let grpcroute_fut = self.run_grpcroute_controller(Arc::clone(&translator));
        let tlsroute_fut = self.run_tlsroute_controller(Arc::clone(&translator));
        let ingress_fut = self.run_ingress_controller();
        let refgrant_fut = self.run_reference_grant_watcher();
        let secret_fut = self.run_secret_watcher(Arc::clone(&translator));

        tokio::select! {
            res = gateway_class_fut => {
                error!("GatewayClass controller exited: {:?}", res);
            }
            res = gateway_fut => {
                error!("Gateway controller exited: {:?}", res);
            }
            res = httproute_fut => {
                error!("HTTPRoute controller exited: {:?}", res);
            }
            res = grpcroute_fut => {
                error!("GRPCRoute controller exited: {:?}", res);
            }
            res = tlsroute_fut => {
                error!("TLSRoute controller exited: {:?}", res);
            }
            res = ingress_fut => {
                error!("Ingress controller exited: {:?}", res);
            }
            res = refgrant_fut => {
                error!("ReferenceGrant watcher exited: {:?}", res);
            }
            res = secret_fut => {
                error!("Secret watcher exited: {:?}", res);
            }
        }

        Ok(())
    }

    async fn run_gateway_class_controller(&self) -> Result<(), GatewayError> {
        let reconciler = Arc::new(GatewayClassReconciler::new(self.client.clone()));
        let api: Api<GatewayClass> = Api::all(self.client.clone());

        Controller::new(api, watcher::Config::default())
            .run(
                move |obj, _ctx| {
                    let reconciler = Arc::clone(&reconciler);
                    async move { reconciler.reconcile(obj).await }
                },
                GatewayClassReconciler::error_policy,
                Arc::new(()),
            )
            .for_each(|res| async move {
                match res {
                    Ok((_obj, _action)) => {}
                    Err(e) => error!(error = %e, "GatewayClass reconciliation error"),
                }
            })
            .await;

        Ok(())
    }

    async fn run_gateway_controller(&self) -> Result<(), GatewayError> {
        let reconciler = Arc::new(GatewayReconciler::new(self.client.clone()));
        let api: Api<Gateway> = Api::all(self.client.clone());

        Controller::new(api, watcher::Config::default())
            .run(
                move |obj, _ctx| {
                    let reconciler = Arc::clone(&reconciler);
                    async move { reconciler.reconcile(obj).await }
                },
                GatewayReconciler::error_policy,
                Arc::new(()),
            )
            .for_each(|res| async move {
                match res {
                    Ok((_obj, _action)) => {}
                    Err(e) => error!(error = %e, "Gateway reconciliation error"),
                }
            })
            .await;

        Ok(())
    }

    async fn run_httproute_controller(
        &self,
        translator: Arc<ConfigTranslator>,
    ) -> Result<(), GatewayError> {
        let reconciler = Arc::new(HttpRouteReconciler::new(self.client.clone(), translator));
        let api: Api<HTTPRoute> = Api::all(self.client.clone());

        Controller::new(api, watcher::Config::default())
            .run(
                move |obj, _ctx| {
                    let reconciler = Arc::clone(&reconciler);
                    async move { reconciler.reconcile(obj).await }
                },
                HttpRouteReconciler::error_policy,
                Arc::new(()),
            )
            .for_each(|res| async move {
                match res {
                    Ok((_obj, _action)) => {}
                    Err(e) => error!(error = %e, "HTTPRoute reconciliation error"),
                }
            })
            .await;

        Ok(())
    }

    async fn run_grpcroute_controller(
        &self,
        translator: Arc<ConfigTranslator>,
    ) -> Result<(), GatewayError> {
        let reconciler = Arc::new(GrpcRouteReconciler::new(self.client.clone(), translator));
        let api: Api<GRPCRoute> = Api::all(self.client.clone());

        Controller::new(api, watcher::Config::default())
            .run(
                move |obj, _ctx| {
                    let reconciler = Arc::clone(&reconciler);
                    async move { reconciler.reconcile(obj).await }
                },
                GrpcRouteReconciler::error_policy,
                Arc::new(()),
            )
            .for_each(|res| async move {
                match res {
                    Ok((_obj, _action)) => {}
                    Err(e) => error!(error = %e, "GRPCRoute reconciliation error"),
                }
            })
            .await;

        Ok(())
    }

    async fn run_tlsroute_controller(
        &self,
        translator: Arc<ConfigTranslator>,
    ) -> Result<(), GatewayError> {
        let reconciler = Arc::new(TlsRouteReconciler::new(self.client.clone(), translator));
        let api: Api<TLSRoute> = Api::all(self.client.clone());

        Controller::new(api, watcher::Config::default())
            .run(
                move |obj, _ctx| {
                    let reconciler = Arc::clone(&reconciler);
                    async move { reconciler.reconcile(obj).await }
                },
                TlsRouteReconciler::error_policy,
                Arc::new(()),
            )
            .for_each(|res| async move {
                match res {
                    Ok((_obj, _action)) => {}
                    Err(e) => error!(error = %e, "TLSRoute reconciliation error"),
                }
            })
            .await;

        Ok(())
    }

    async fn run_ingress_controller(&self) -> Result<(), GatewayError> {
        let reconciler = Arc::new(IngressReconciler::new(self.client.clone()));
        let api: Api<Ingress> = Api::all(self.client.clone());

        Controller::new(api, watcher::Config::default())
            .run(
                move |obj, _ctx| {
                    let reconciler = Arc::clone(&reconciler);
                    async move { reconciler.reconcile(obj).await }
                },
                IngressReconciler::error_policy,
                Arc::new(()),
            )
            .for_each(|res| async move {
                match res {
                    Ok((_obj, _action)) => {}
                    Err(e) => error!(error = %e, "Ingress reconciliation error"),
                }
            })
            .await;

        Ok(())
    }

    /// Watch ReferenceGrant resources and rebuild the index on changes.
    async fn run_reference_grant_watcher(&self) -> Result<(), GatewayError> {
        use kube::runtime::watcher as kube_watcher;

        let api: Api<ReferenceGrant> = Api::all(self.client.clone());
        let mut stream =
            kube_watcher::watcher(api, kube_watcher::Config::default()).boxed();

        while let Some(event) = stream.next().await {
            match event {
                Ok(_) => {
                    // Rebuild on any change
                    if let Err(e) = self.rebuild_reference_grants().await {
                        error!(error = %e, "Failed to rebuild ReferenceGrant index");
                    }
                }
                Err(e) => {
                    error!(error = %e, "ReferenceGrant watch error");
                }
            }
        }

        Ok(())
    }

    /// Watch Secret resources and refresh TLS certificates when they change.
    ///
    /// When a Secret referenced by a Gateway's TLS config changes, the
    /// certificate files are updated on disk and a config rebuild is triggered
    /// so the proxy picks up the new certificates.
    async fn run_secret_watcher(
        &self,
        translator: Arc<ConfigTranslator>,
    ) -> Result<(), GatewayError> {
        use kube::runtime::watcher as kube_watcher;

        let api: Api<Secret> = Api::all(self.client.clone());
        // Only watch TLS secrets
        let config = kube_watcher::Config::default()
            .fields("type=kubernetes.io/tls");
        let mut stream = kube_watcher::watcher(api, config).boxed();

        while let Some(event) = stream.next().await {
            match event {
                Ok(_) => {
                    let errors = self.cert_manager.refresh_all().await;
                    if errors.is_empty() {
                        // Trigger config rebuild to pick up new cert paths
                        if let Err(e) = translator.rebuild(&self.client).await {
                            warn!(error = %e, "Config rebuild after Secret change failed");
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Secret watch error");
                }
            }
        }

        Ok(())
    }

    /// Rebuild the ReferenceGrant index from cluster state.
    async fn rebuild_reference_grants(&self) -> Result<(), GatewayError> {
        let api: Api<ReferenceGrant> = Api::all(self.client.clone());
        let grants = api.list(&ListParams::default()).await?;
        self.reference_grants.rebuild(grants.items);
        Ok(())
    }
}
