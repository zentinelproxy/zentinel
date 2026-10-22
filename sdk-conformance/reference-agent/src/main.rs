//! The conformance agent from `sdk-conformance/README.md`, on the protocol
//! crate's own servers.
//!
//! `reference-agent --socket PATH` or `reference-agent --grpc HOST:PORT`.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine as _;
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentHandlerV2, GrpcAgentServerV2, UdsAgentServerV2,
};
use zentinel_agent_protocol::{
    AgentResponse, EventType, HeaderOp, RequestBodyChunkEvent, RequestHeadersEvent,
    ResponseHeadersEvent,
};

#[derive(Default)]
struct Conformance {
    config: Mutex<Option<serde_json::Value>>,
    bodies: Mutex<HashMap<String, Vec<u8>>>,
}

fn set(name: &str, value: &str) -> HeaderOp {
    HeaderOp::Set {
        name: name.to_string(),
        value: value.to_string(),
    }
}

#[async_trait]
impl AgentHandlerV2 for Conformance {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("conformance-reference", "conformance-reference", "0.0.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
            .with_event(EventType::ResponseHeaders)
    }

    async fn on_configure(&self, config: serde_json::Value, _version: Option<String>) -> bool {
        *self.config.lock().unwrap() = Some(config);
        true
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        if event.uri.starts_with("/block") {
            return AgentResponse::block(403, Some("blocked-by-agent".to_string()));
        }
        let value = self
            .config
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|c| c["nested"]["value"].as_str().map(str::to_string))
            .unwrap_or_else(|| "unconfigured".to_string());
        AgentResponse::default_allow()
            .add_request_header(set("X-Hello", "from-agent"))
            .add_request_header(set("X-Conformance-Config", &value))
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let chunk = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        let mut bodies = self.bodies.lock().unwrap();
        let body = bodies.entry(event.correlation_id.clone()).or_default();
        body.extend_from_slice(&chunk);
        if !event.is_last {
            let mut more = AgentResponse::default_allow();
            more.needs_more = true;
            return more;
        }
        let body = bodies.remove(&event.correlation_id).unwrap_or_default();
        let text = String::from_utf8_lossy(&body);
        if text.contains("block-this-body") {
            return AgentResponse::block(403, Some(format!("body-seen:{text}")));
        }
        AgentResponse::default_allow()
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
            .add_response_header(set("X-Conformance-Response", "from-agent"))
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let handler = Box::new(Conformance::default());
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("--socket"), Some(path)) => {
            UdsAgentServerV2::new("conformance-reference", path, handler)
                .run()
                .await
                .expect("uds server")
        }
        (Some("--grpc"), Some(addr)) => GrpcAgentServerV2::new("conformance-reference", handler)
            .run(addr.parse().expect("host:port"))
            .await
            .expect("grpc server"),
        _ => {
            eprintln!("usage: reference-agent --socket PATH | --grpc HOST:PORT");
            std::process::exit(2);
        }
    }
}
