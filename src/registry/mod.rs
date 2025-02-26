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
use stof::SDoc;


/// Add a stof document to this registry.
pub(crate) fn add_registry_doc(path: &str, format: &str, mut doc: SDoc) -> bool {
    let mut buf = path.split("/").collect::<Vec<&str>>();
    buf.pop();
    let buf = buf.join("/");
    let _ = fs::create_dir_all(&buf);

    let res;
    if format == "bstof" {
        res = doc.bin_file_out(path, format);
    } else {
        res = doc.text_file_out(path, format);
    }
    res.is_ok()
}

/// Get a stof document from the registry.
pub(crate) fn get_registry_doc(path: &str, format: &str) -> Option<SDoc> {
    if let Ok(doc) = SDoc::file(path, format) {
        Some(doc)
    } else {
        None
    }
}

/// Delete a stof document from the registry.
pub(crate) fn delete_registry_doc(path: &str) -> bool {
    fs::remove_file(path).is_ok()
}
