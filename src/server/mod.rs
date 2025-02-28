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
use http_auth_basic::Credentials;
use response::StofResponse;

mod sandbox_fs;
use sandbox_fs::TmpFileSystemLibrary;
use stof_http::HTTPLibrary;

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use axum::{body::Bytes, extract::{Path, Query, State}, http::{header::{AUTHORIZATION, CONTENT_TYPE}, HeaderMap, StatusCode}, response::IntoResponse, routing::{get, post}, Router};
use stof::{SDoc, SField, SUnits, SVal};
use tokio::{sync::Mutex, time::timeout};
use tower_governor::{governor::GovernorConfig, GovernorLayer};
use tower_http::cors::CorsLayer;

use crate::{admin_delete_user, admin_set_user, can_exec, can_modify_registry, can_read_registry, get_admin, load_users, registry::{add_registry_pkg, delete_registry_pkg, get_registry_pkg, LPKG}};


/// Server state.
#[derive(Clone)]
pub struct ServerState {
    /// Configuration document.
    pub config: Arc<Mutex<SDoc>>,

    /// (path.bstof, users document).
    pub users: Arc<Mutex<(String, SDoc)>>,
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
    let users = load_users(&config);
    let state = ServerState {
        config: Arc::new(Mutex::new(config)),
        users: Arc::new(Mutex::new(users)),
    };

    // Create the application router
    let app = Router::new()
        // Registry API
        .route("/registry/{*path}", get(get_registry_handler)
            .put(put_registry_handler)
            .delete(delete_registry_handler))
        
        // Exec API
        .route("/run", post(exec_handler))
        
        // Admin Users API
        .route("/admin/users", post(admin_set_user_handler)
            .delete(admin_delete_user_handler))
        
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
    // Replace the fs library with one that can only access the TMP directory
    doc.load_lib(Arc::new(TmpFileSystemLibrary::default()));

    // Add HTTP library
    doc.load_lib(Arc::new(HTTPLibrary::default()));

    // Add local pkg registry format, replacing the native Stof PKG format
    doc.load_format(Arc::new(LPKG::new(state.registry_path().await)));
}


/*****************************************************************************
 * Registry API.
 *****************************************************************************/

/// Put request handler - add a package to the registry.
async fn put_registry_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    if !state.registry_enabled().await {
        return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "registry is not enabled");
    }
    if path.split('/').collect::<Vec<&str>>().len() < 2 {
        return StofResponse::error(StatusCode::BAD_REQUEST, "package directory not found");
    }

    // authorization for modifying this registry
    // basic "Authorization" header access, with base64 encoding of "user:pass". Ex. "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
    {
        let mut config = state.config.lock().await;
        if let Some(admin) = get_admin(&config) {
            if let Some(authorization) = headers.get(AUTHORIZATION) {
                if let Ok(credentials) = Credentials::from_header(authorization.to_str().unwrap().to_string()) {
                    let user = credentials.user_id;
                    let pass = credentials.password;

                    if user == admin.0 && pass == admin.1 {
                        // granted access as admin
                    } else {
                        // need to check with users for access
                        let mut pair = state.users.lock().await;
                        if !can_modify_registry(&mut pair, &user, &pass, &path) {
                            return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                        }
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            } else {
                if let Ok(res) = config.call_func("root.unauth_modify", None, vec![]) {
                    if !res.truthy() {
                        return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            }
        }
    }

    let registry_path = state.registry_path().await;
    let path = format!("{}/{}", registry_path, path);
    
    let mut overwrite = true;
    if let Some(q_overwrite) = query.get("overwrite") {
        overwrite = q_overwrite == "true";
    }
    
    if add_registry_pkg(&path, overwrite, body) {
        StofResponse::msg(StatusCode::OK, "package created")
    } else {
        StofResponse::error(StatusCode::BAD_REQUEST, "package not created")
    }
}

/// Delete request handler - remove an interface from the registry.
async fn delete_registry_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(_query): Query<BTreeMap<String, String>>, headers: HeaderMap, _body: Bytes) -> impl IntoResponse {
    if !state.registry_enabled().await {
        return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "registry is not enabled");
    }
    if path.split('/').collect::<Vec<&str>>().len() < 2 {
        return StofResponse::error(StatusCode::BAD_REQUEST, "package directory not found");
    }

    // authorization for modifying this registry
    // basic "Authorization" header access, with base64 encoding of "user:pass". Ex. "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
    {
        let mut config = state.config.lock().await;
        if let Some(admin) = get_admin(&config) {
            if let Some(authorization) = headers.get(AUTHORIZATION) {
                if let Ok(credentials) = Credentials::from_header(authorization.to_str().unwrap().to_string()) {
                    let user = credentials.user_id;
                    let pass = credentials.password;

                    if user == admin.0 && pass == admin.1 {
                        // granted access as admin
                    } else {
                        // need to check with users for access
                        let mut pair = state.users.lock().await;
                        if !can_modify_registry(&mut pair, &user, &pass, &path) {
                            return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                        }
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            } else {
                if let Ok(res) = config.call_func("root.unauth_modify", None, vec![]) {
                    if !res.truthy() {
                        return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            }
        }
    }

    let registry_path = state.registry_path().await;
    let path = format!("{}/{}", registry_path, path);

    if delete_registry_pkg(&path) {
        return StofResponse::msg(StatusCode::OK, "package removed");
    }
    StofResponse::error(StatusCode::NOT_FOUND, "package not found")
}

/// Get request handler - get an interface from a registry.
async fn get_registry_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(_query): Query<BTreeMap<String, String>>, headers: HeaderMap) -> impl IntoResponse {
    if !state.registry_enabled().await {
        return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "registry is not enabled");
    }
    if path.split('/').collect::<Vec<&str>>().len() < 2 {
        return StofResponse::error(StatusCode::BAD_REQUEST, "package directory not found");
    }

    // authorization for reading this registry
    // basic "Authorization" header access, with base64 encoding of "user:pass". Ex. "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
    {
        let mut config = state.config.lock().await;
        if let Some(admin) = get_admin(&config) {
            if let Some(authorization) = headers.get(AUTHORIZATION) {
                if let Ok(credentials) = Credentials::from_header(authorization.to_str().unwrap().to_string()) {
                    let user = credentials.user_id;
                    let pass = credentials.password;

                    if user == admin.0 && pass == admin.1 {
                        // granted access as admin
                    } else {
                        // need to check with users for access
                        let mut pair = state.users.lock().await;
                        if !can_read_registry(&mut pair, &user, &pass) {
                            return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                        }
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            } else {
                if let Ok(res) = config.call_func("root.unauth_read", None, vec![]) {
                    if !res.truthy() {
                        return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            }
        }
    }
    
    let registry_path = state.registry_path().await;
    let path = format!("{}/{}", registry_path, path);

    if let Some(bytes) = get_registry_pkg(&path) {
        return StofResponse::bytes(StatusCode::OK, bytes);
    }
    StofResponse::error(StatusCode::NOT_FOUND, "package not found")
}


/*****************************************************************************
 * Exec API.
 *****************************************************************************/

/// Post request handler - run some stof.
async fn exec_handler(State(state): State<ServerState>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, mut body: Bytes) -> impl IntoResponse {
    if !state.run_stof().await {
        return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "stof runner is not enabled");
    }

    // authorization for execution
    // basic "Authorization" header access, with base64 encoding of "user:pass". Ex. "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
    {
        let mut config = state.config.lock().await;
        if let Some(admin) = get_admin(&config) {
            if let Some(authorization) = headers.get(AUTHORIZATION) {
                if let Ok(credentials) = Credentials::from_header(authorization.to_str().unwrap().to_string()) {
                    let user = credentials.user_id;
                    let pass = credentials.password;

                    if user == admin.0 && pass == admin.1 {
                        // granted access as admin
                    } else {
                        // need to check with users for access
                        let mut pair = state.users.lock().await;
                        if !can_exec(&mut pair, &user, &pass) {
                            return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                        }
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            } else {
                if let Ok(res) = config.call_func("root.unauth_exec", None, vec![]) {
                    if !res.truthy() {
                        return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            }
        }
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


/*****************************************************************************
 * Admin Users API.
 *****************************************************************************/

/// Create/update a user in this registry.
async fn admin_set_user_handler(State(state): State<ServerState>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    // authorization for admin API
    // basic "Authorization" header access, with base64 encoding of "user:pass". Ex. "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
    {
        let config = state.config.lock().await;
        if let Some(admin) = get_admin(&config) {
            if let Some(authorization) = headers.get(AUTHORIZATION) {
                if let Ok(credentials) = Credentials::from_header(authorization.to_str().unwrap().to_string()) {
                    let user = credentials.user_id;
                    let pass = credentials.password;
                    if user == admin.0 && pass == admin.1 {
                        // granted access as admin
                    } else {
                        return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            } else {
                return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
            }
        } else {
            return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "not available");
        }
    }
    
    let mut content_type = String::from("stof");
    if let Some(ctype) = headers.get(CONTENT_TYPE) {
        content_type = ctype.to_str().unwrap().to_owned();
    }
    if let Ok(doc) = SDoc::bytes(body, &content_type) {
        if let Some(user) = doc.field("root.username", None) {
            if let Some(pass) = doc.field("root.password", None) {
                if let Some(perms) = doc.field("root.perms", None) {
                    let mut scope = String::default();
                    if let Some(scope_field) = doc.field("root.scope", None) {
                        scope = scope_field.to_string();
                    }
                    match &perms.value {
                        SVal::Number(num) => {
                            let perms = num.int();
                            let mut pair = state.users.lock().await;
                            if admin_set_user(&mut pair, &user.to_string(), &pass.to_string(), perms, &scope) {
                                return StofResponse::msg(StatusCode::OK, "set user");
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
    }
    StofResponse::error(StatusCode::BAD_REQUEST, "not a valid user body")
}

/// Delete a user in this registry.
async fn admin_delete_user_handler(State(state): State<ServerState>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    // authorization for admin API
    // basic "Authorization" header access, with base64 encoding of "user:pass". Ex. "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
    {
        let config = state.config.lock().await;
        if let Some(admin) = get_admin(&config) {
            if let Some(authorization) = headers.get(AUTHORIZATION) {
                if let Ok(credentials) = Credentials::from_header(authorization.to_str().unwrap().to_string()) {
                    let user = credentials.user_id;
                    let pass = credentials.password;
                    if user == admin.0 && pass == admin.1 {
                        // granted access as admin
                    } else {
                        return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                    }
                } else {
                    return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
                }
            } else {
                return StofResponse::error(StatusCode::FORBIDDEN, "access denied");
            }
        } else {
            return StofResponse::error(StatusCode::NOT_IMPLEMENTED, "not available");
        }
    }
    
    let mut content_type = String::from("stof");
    if let Some(ctype) = headers.get(CONTENT_TYPE) {
        content_type = ctype.to_str().unwrap().to_owned();
    }
    if let Ok(doc) = SDoc::bytes(body, &content_type) {
        if let Some(user) = doc.field("root.username", None) {
            let mut pair = state.users.lock().await;
            if admin_delete_user(&mut pair, &user.to_string()) {
                return StofResponse::msg(StatusCode::OK, "deleted");
            }
        }
    }
    StofResponse::error(StatusCode::BAD_REQUEST, "not a valid user body")
}
