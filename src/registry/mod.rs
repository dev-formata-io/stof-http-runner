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

use std::{fs, io, path::PathBuf};
use bytes::Bytes;
use nanoid::nanoid;
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

    if let Ok(file) = fs::File::open(&file_path) {
        if let Ok(mut archive) = zip::ZipArchive::new(file) {
            let tmp_dir_name = nanoid!();
            let _ = fs::create_dir_all(&tmp_dir_name);

            // extract all files to the temp dir location
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).unwrap();
                
                let outname = match file.enclosed_name() {
                    Some(path) => path,
                    None => continue,
                };
                
                let mut outpath = PathBuf::from(&tmp_dir_name);
                outpath.push(outname);
                
                if file.is_dir() {
                    let _ = fs::create_dir_all(&outpath);
                } else {
                    if let Some(p) = outpath.parent() {
                        if !p.exists() {
                            let _ = fs::create_dir_all(p);
                        }
                    }
                    if let Ok(mut outfile) = fs::File::create(&outpath) {
                        let _ = io::copy(&mut file, &mut outfile);
                    }
                }
            }

            // import the package into a document
            if let Ok(doc) = SDoc::file(&format!("{}.stof", tmp_dir_name), "pkg") {
                let _ = fs::remove_dir_all(&tmp_dir_name);
                return Some(doc);
            }
            let _ = fs::remove_dir_all(&tmp_dir_name);
        }
    }
    None
}
