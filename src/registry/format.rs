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

use std::fs;
use axum::body::Bytes;
use stof::{lang::SError, Format};


/// Local registry format.
pub struct LocalRegistryFormat {
    pub registry: String,
}
impl Format for LocalRegistryFormat {
    /// Format identifier.
    fn format(&self) -> String {
        "reg:local".to_string()
    }

    /// File import.
    fn file_import(&self, pid: &str, doc: &mut stof::SDoc, _format: &str, full_path: &str, _extension: &str, as_name: &str) -> Result<(), stof::lang::SError> {
        let mut path = format!("{}/{}", self.registry, full_path);
        if !path.ends_with(".bstof") {
            let mut buf = path.split('.').collect::<Vec<&str>>();
            if buf.len() > 1 {
                buf.pop();
                path = buf.join(".");
            }
            path = format!("{}.bstof", path);
        }
        if let Ok(bytes) = fs::read(&path) {
            return doc.header_import(pid, "bstof", "bstof", &mut Bytes::from(bytes), as_name);
        }
        Err(SError::custom(pid, doc, "LocalRegistryError", "document not found"))
    }
}
