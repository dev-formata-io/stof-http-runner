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

use std::str::FromStr;
use axum::{body::{Body, Bytes}, http::{header::CONTENT_TYPE, HeaderMap, HeaderName, Response, StatusCode}, response::IntoResponse};
use stof::{SDoc, SVal};


/// Response object, implementing IntoResonse.
pub struct StofResponse {
    pub headers: HeaderMap,
    pub status: StatusCode,
    pub str_body: String,
    pub bytes_body: Option<Bytes>, // if present, will get sent in place of the str_body
}
impl IntoResponse for StofResponse {
    fn into_response(self) -> axum::response::Response {
        let mut builder = Response::builder().status(self.status);
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        let response;
        if let Some(bytes) = self.bytes_body {
            if !self.headers.contains_key(CONTENT_TYPE) {
                builder = builder.header(CONTENT_TYPE, "application/octet-stream");
            }
            response = builder.body(Body::from(bytes));
        } else {
            if !self.headers.contains_key(CONTENT_TYPE) {
                builder = builder.header(CONTENT_TYPE, "text/plain");
            }
            response = builder.body(Body::from(self.str_body));
        }
        response.unwrap()
    }
}
impl StofResponse {
    /// Creates a response from this value with a success status code.
    #[allow(unused)]
    pub fn val_response(doc: &SDoc, value: SVal) -> Self {
        let mut status = StatusCode::OK;
        let mut headers = HeaderMap::new();
        let mut str_body = String::default();
        let mut bytes_body = None;
        let match_val = value.unbox();
        match match_val {
            SVal::Blob(blob) => {
                headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
                bytes_body = Some(Bytes::from(blob));
            },
            SVal::String(value) => {
                headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
                str_body = value;
            },
            SVal::Map(map) => {
                if let Some(format_val) = map.get(&SVal::String("format".into())) {
                    if let Some(format) = doc.formats.get(&format_val.to_string()) {
                        headers.insert("format", format.format().parse().unwrap());
                        headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                    }
                }
                if let Some(headers_val) = map.get(&SVal::String("headers".into())) {
                    match headers_val {
                        SVal::Map(headers_map) => {
                            for (k, v) in headers_map {
                                let key = k.to_string();
                                headers.insert(HeaderName::from_str(&key).unwrap(), v.to_string().parse().unwrap());
                            }
                        },
                        SVal::Array(values) => {
                            for tup in values {
                                match tup {
                                    SVal::Tuple(tup) => {
                                        if tup.len() == 2 {
                                            let key = tup[0].to_string();
                                            headers.insert(HeaderName::from_str(&key).unwrap(), tup[1].to_string().parse().unwrap());
                                        }
                                    },
                                    _ => {}
                                }
                            }
                        },
                        _ => {}
                    }
                }
                if let Some(body_val) = map.get(&SVal::String("body".into())) {
                    // Get content type to use from the headers if any
                    let content_type = headers.get(CONTENT_TYPE);

                    match body_val {
                        SVal::String(value) => {
                            if content_type.is_none() { // give opportunity to override with the map above
                                headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
                            }
                            str_body = value.clone();
                        },
                        SVal::Blob(blob) => {
                            if content_type.is_none() { // give opportunity to override with the map above
                                headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
                            }
                            bytes_body = Some(Bytes::from(blob.clone()));
                        },
                        SVal::Object(nref) => {
                            let format;
                            if let Some(value) = headers.get("format") {
                                format = value.to_str().unwrap().to_owned();
                            } else if let Some(ctype) = content_type {
                                format = ctype.to_str().unwrap().to_owned();
                            } else {
                                format = "json".to_owned();
                            }
                            if let Ok(result) = doc.export_string("main", &format, Some(nref)) {
                                str_body = result;
                                if let Some(format) = doc.formats.get(&format) {
                                    headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                                }
                            } else if let Ok(result) = doc.export_bytes("main", &format, Some(nref)) {
                                bytes_body = Some(result);
                                if let Some(format) = doc.formats.get(&format) {
                                    headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                                }
                            } else if let Ok(result) = doc.export_bytes("main", "bytes", Some(nref)) {
                                bytes_body = Some(result);
                                if let Some(format) = doc.formats.get("bytes") {
                                    headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                                }
                            }
                        },
                        _ => {}
                    }
                }
                if let Some(status_val) = map.get(&SVal::String("status".into())) {
                    let status_res = StatusCode::from_str(&status_val.to_string());
                    match status_res {
                        Ok(code) => status = code,
                        Err(_inv) => status = StatusCode::MULTI_STATUS,
                    }
                }
            },
            _ => {}
        }
        Self {
            status,
            headers,
            str_body,
            bytes_body,
        }
    }

    /// Message response.
    pub fn msg(code: StatusCode, message: &str) -> Self {
        Self {
            headers: HeaderMap::new(),
            status: code,
            str_body: message.to_owned(),
            bytes_body: None,
        }
    }

    /// Error response.
    pub fn error(code: StatusCode, message: &str) -> Self {
        Self {
            headers: HeaderMap::new(),
            status: code,
            str_body: message.to_owned(),
            bytes_body: None,
        }
    }

    /// BSTOF response.
    pub fn bstof(code: StatusCode, bytes: Bytes) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/bstof".parse().unwrap());

        Self {
            headers,
            status: code,
            str_body: Default::default(),
            bytes_body: Some(bytes),
        }
    }
}
