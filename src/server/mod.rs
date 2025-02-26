//
// Copyright 2024 Formata, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

mod response;
use response::StofResponse;

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use axum::{body::Bytes, extract::{Path, Query, State}, http::{header::CONTENT_TYPE, HeaderMap, StatusCode}, response::IntoResponse, routing::{get, post}, Router};
use stof::{FileSystemLibrary, SDoc, SField, SUnits, SVal};
use tokio::{sync::Mutex, time::timeout};
use tower_governor::{governor::GovernorConfig, GovernorLayer};
use tower_http::cors::CorsLayer;

use crate::registry::{add_registry_doc, delete_registry_doc, get_registry_doc, LocalRegistryFormat};


/// Server state.
#[derive(Clone)]
pub struct ServerState {
    pub config: Arc<Mutex<SDoc>>,
}
impl ServerState {
    /// Return specific stof errors?
    pub async fn stof_errors(&self) -> bool {
        let config = self.config.lock().await;
        if let Some(errors_path) = SField::field(&config.graph, "root.server.errors", '.', None) {
            match &errors_path.value {
                SVal::Bool(val) => {
                    return *val;
                },
                _ => {}
            }
        }
        false
    }

    /// Can execute stof?
    pub async fn run_stof(&self) -> bool {
        let config = self.config.lock().await;
        if let Some(run_stof) = SField::field(&config.graph, "root.server.run_stof", '.', None) {
            match &run_stof.value {
                SVal::Bool(val) => {
                    return *val;
                },
                _ => {}
            }
        }
        false
    }

    /// Run timeout.
    pub async fn run_timeout(&self) -> Duration {
        let mut config = self.config.lock().await;
        if let Ok(res) = config.call_func("root.server.timeout", None, vec![]) {
            // returns number in seconds
            match res {
                SVal::Number(num) => {
                    return Duration::from_secs(num.float_with_units(SUnits::Seconds) as u64);
                },
                _ => {}
            }
        }
        Duration::from_secs(10)
    }

    /// Registry enabled?
    pub async fn registry_enabled(&self) -> bool {
        let config = self.config.lock().await;
        if let Some(enabled_field) = SField::field(&config.graph, "root.registry.enabled", '.', None) {
            match &enabled_field.value {
                SVal::Bool(val) => {
                    return *val;
                },
                _ => {}
            }
        }
        false
    }

    /// Get the registry file path.
    pub async fn registry_path(&self) -> String {
        let mut path = String::from("registry");
        let config = self.config.lock().await;
        if let Some(registry_path) = SField::field(&config.graph, "root.registry.path", '.', None) {
            path = registry_path.to_string();
        }
        path
    }
}

/// Start the runner HTTP server.
/// Stof - open-source, natural language LLM & API connector framework - MCP + APIs + Orchestration & Logic.
pub async fn run_server(config: SDoc) {
    let mut port = 3030;
    let mut ip = [127, 0, 0, 1];
    if let Some(ip_field) = SField::field(&config.graph, "root.server.address", '.', None) {
        match &ip_field.value {
            SVal::Array(vals) => {
                if vals.len() == 4 {
                    for i in 0..4 {
                        match &vals[i] {
                            SVal::Number(num) => {
                                ip[i] = num.int() as u8;
                            },
                            _ => {}
                        }
                    }
                }
            },
            _ => {}
        }
    }
    if let Some(port_field) = SField::field(&config.graph, "root.server.port", '.', None) {
        match &port_field.value {
            SVal::Number(num) => {
                port = num.int() as u16;
            },
            _ => {}
        }
    }
    let address = SocketAddr::from((ip, port));

    // Setup governor configuration - see https://crates.io/crates/tower_governor
    let governor_conf = Arc::new(GovernorConfig::default());
    let governor_limiter = governor_conf.limiter().clone();
    let interval = Duration::from_secs(60);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            governor_limiter.retain_recent();
        }
    });

    // Cors layer
    let cors = CorsLayer::permissive();

    // Server state
    let state = ServerState {
        config: Arc::new(Mutex::new(config)),
    };

    // Create the application router
    let app = Router::new()
        .route("/registry/{*path}", get(get_request_handler)
            .put(put_request_handler)
            .delete(delete_request_handler))
        .route("/run", post(post_request_handler))
        .layer(GovernorLayer {
            config: governor_conf
        })
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

/// Sandbox a document for execution on this server.
/// Add libraries that this server offers.
pub async fn sandbox_document(doc: &mut SDoc, state: ServerState) {
    doc.libraries.libraries.remove("fs");

    // Add local registry format
    doc.load_format(Arc::new(LocalRegistryFormat {
        registry: state.registry_path().await,
    }));
}

/// Add fs library to a document.
fn add_fs(doc: &mut SDoc) {
    doc.load_lib(Arc::new(FileSystemLibrary::default()));
}

/// Put request handler - add an interface to the registry.
async fn put_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(_query): Query<BTreeMap<String, String>>, headers: HeaderMap, mut body: Bytes) -> impl IntoResponse {
    if !state.registry_enabled().await {
        return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "registry is not enabled");
    }
    
    let mut content_type = String::from("stof");
    if let Some(ctype) = headers.get(CONTENT_TYPE) {
        content_type = ctype.to_str().unwrap().to_owned();
    }
    
    let mut doc = SDoc::default();
    sandbox_document(&mut doc, state.clone()).await;
    let res = doc.header_import("main", &content_type, &content_type, &mut body, "");
    match res {
        Ok(_) => {
            let registry_path = state.registry_path().await;
            let mut path = format!("{}/{}", registry_path, path);
            if !path.ends_with(".bstof") {
                path = format!("{}.bstof", path);
            }

            add_fs(&mut doc); // needed for adding to registry
            let res = add_registry_doc(&path, "bstof", doc);
            if !res {
                return StofResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "error creating registry document");
            }
            StofResponse::msg(StatusCode::OK, "successfully added document")
        },
        Err(error) => {
            let stof_errors = state.stof_errors().await;
            if stof_errors {
                return StofResponse::error(StatusCode::BAD_REQUEST, &error.to_string(&doc.graph));
            }
            StofResponse::error(StatusCode::BAD_REQUEST, "error creating document")
        },
    }
}

/// Delete request handler - remove an interface from the registry.
async fn delete_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(_query): Query<BTreeMap<String, String>>, _headers: HeaderMap, _body: Bytes) -> impl IntoResponse {
    if !state.registry_enabled().await {
        return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "registry is not enabled");
    }

    let registry_path = state.registry_path().await;
    let mut path = format!("{}/{}", registry_path, path);
    if !path.ends_with(".bstof") {
        path = format!("{}.bstof", path);
    }

    if delete_registry_doc(&path) {
        return StofResponse::msg(StatusCode::OK, "successfully removed document");
    }
    StofResponse::error(StatusCode::NOT_FOUND, "did not find a document in this location")
}

/// Get request handler - get an interface from a registry.
async fn get_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(_query): Query<BTreeMap<String, String>>, _headers: HeaderMap) -> impl IntoResponse {
    if !state.registry_enabled().await {
        return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "registry is not enabled");
    }
    
    let registry_path = state.registry_path().await;
    let mut path = format!("{}/{}", registry_path, path);
    if !path.ends_with(".bstof") {
        path = format!("{}.bstof", path);
    }

    if let Some(doc) = get_registry_doc(&path, "bstof") {
        if let Ok(bytes) = doc.export_bytes("main", "bstof", None) {
            return StofResponse::bstof(StatusCode::OK, bytes);
        }
    }
    StofResponse::error(StatusCode::NOT_FOUND, "document not found")
}

/// Post request handler - run some stof.
async fn post_request_handler(State(state): State<ServerState>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, mut body: Bytes) -> impl IntoResponse {
    if !state.run_stof().await {
        return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "stof runner is not enabled");
    }
    let time = state.run_timeout().await;
    let result = timeout(time, async move {
        let mut content_type = String::from("stof");
        if let Some(ctype) = headers.get(CONTENT_TYPE) {
            content_type = ctype.to_str().unwrap().to_owned();
        }
        
        let mut doc = SDoc::default();
        sandbox_document(&mut doc, state.clone()).await;
        let res = doc.header_import("main", &content_type, &content_type, &mut body, "");
        match res {
            Ok(_) => {
                // Execute the main root as a task
                if let Some(main) = doc.graph.main_root() {
                    if let Some(lib) = doc.libraries.get("Object") {
                        let res = lib.call("main", &mut doc, "exec", &mut vec![SVal::Object(main)]);
                        match res {
                            Ok(_) => {
                                // Nothing to do here...
                            },
                            Err(res) => {
                                let stof_errors = state.stof_errors().await;
                                if stof_errors {
                                    return StofResponse::error(StatusCode::BAD_REQUEST, &res.to_string(&doc.graph));
                                }
                                return StofResponse::error(StatusCode::BAD_REQUEST, "error executing document");
                            },
                        }
                    }
                }

                // Run the main functions in this document
                let res = doc.run(None);
                match res {
                    Ok(_) => {
                        // Nothing to do here...
                    },
                    Err(res) => {
                        let stof_errors = state.stof_errors().await;
                        if stof_errors {
                            return StofResponse::error(StatusCode::BAD_REQUEST, &res);
                        }
                        return StofResponse::error(StatusCode::BAD_REQUEST, "error running document");
                    },
                }
            },
            Err(error) => {
                let stof_errors = state.stof_errors().await;
                if stof_errors {
                    return StofResponse::error(StatusCode::BAD_REQUEST, &error.to_string(&doc.graph));
                }
                return StofResponse::error(StatusCode::BAD_REQUEST, "error parsing document");
            },
        }

        if let Some(format) = query.get("export") {
            if let Ok(text) = doc.export_string("main", format, None) {
                if let Some(format) = doc.formats.get(format) {
                    let mut headers = HeaderMap::new();
                    headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                    return StofResponse {
                        headers,
                        status: StatusCode::OK,
                        str_body: text,
                        bytes_body: None,
                    };
                }
            }
        }

        if let Ok(bytes) = doc.export_bytes("main", "bstof", None) {
            return StofResponse::bstof(StatusCode::OK, bytes);
        }
        StofResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "error exporting document")
    }).await;

    match result {
        Ok(res) => {
            res
        },
        Err(_) => {
            StofResponse::error(StatusCode::REQUEST_TIMEOUT, "timeout while running document")
        }
    }
}
