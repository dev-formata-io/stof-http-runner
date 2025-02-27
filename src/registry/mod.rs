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
use bytes::Bytes;
use stof::SDoc;

pub mod format;
pub use format::*;


/// Add a registry package (ZIP file bytes).
pub fn add_registry_pkg(path: &str, overwrite: bool, bytes: Bytes) -> bool {
    let mut buf = path.split("/").collect::<Vec<&str>>();
    buf.pop();
    let buf = buf.join("/");
    let _ = fs::create_dir_all(&buf);

    let mut file_path = path.to_string();
    if !file_path.ends_with(".zip") {
        file_path.push_str(".zip");
    }
    
    let exists = fs::exists(&file_path);
    if exists.is_err() || (!overwrite && exists.unwrap()) {
        return false;
    }

    let res = fs::write(&file_path, bytes);
    res.is_ok()
}

/// Delete a package from the registry.
pub fn delete_registry_pkg(path: &str) -> bool {
    let mut file_path = path.to_string();
    if !file_path.ends_with(".zip") {
        file_path.push_str(".zip");
    }
    fs::remove_file(&file_path).is_ok()
}

/// Get a registry package.
pub fn get_registry_pkg(path: &str) -> Option<Bytes> {
    let mut file_path = path.to_string();
    if !file_path.ends_with(".zip") {
        file_path.push_str(".zip");
    }
    
    let exists = fs::exists(&file_path);
    if exists.is_err() || !exists.unwrap() {
        return None;
    }

    if let Ok(bytes) = fs::read(&file_path) {
        return Some(Bytes::from(bytes));
    }
    None
}

/// Create a registry package document.
pub fn create_registry_doc(path: &str) -> Option<SDoc> {
    let mut file_path = path.to_string();
    if !file_path.ends_with(".zip") {
        file_path.push_str(".zip");
    }
    
    let exists = fs::exists(&file_path);
    if exists.is_err() || !exists.unwrap() {
        return None;
    }

    if let Ok(bytes) = fs::read(&file_path) {
        if let Ok(doc) = SDoc::bytes(Bytes::from(bytes), "pkg") {
            return Some(doc);
        }
    }
    None
}
