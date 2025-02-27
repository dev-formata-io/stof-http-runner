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

use stof::{lang::SError, Format};
use super::create_registry_doc;


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
        let path = format!("{}/{}", self.registry, full_path.trim_end_matches(".stof"));
        if let Some(reg_doc) = create_registry_doc(&path) {
            if let Ok(mut bytes) = reg_doc.export_bytes("main", "bstof", None) {
                return doc.header_import(pid, "bstof", "bstof", &mut bytes, as_name);
            }
        }
        Err(SError::custom(pid, doc, "LocalRegistryError", "document not found"))
    }
}
