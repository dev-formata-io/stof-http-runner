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
use stof::{lang::SError, pkg::PKG, Library, SDoc, SVal};


/// Sandboxed file system library.
/// Used only when importing packages, which allows access to any file currently in the PKG temp directory.
#[derive(Default)]
pub struct TmpFileSystemLibrary {
    pub pkg_format: PKG,
}
impl Library for TmpFileSystemLibrary {
    fn scope(&self) -> String {
        "fs".to_string()
    }

    fn call(&self, pid: &str, doc: &mut SDoc, name: &str, parameters: &mut Vec<SVal>) -> Result<SVal, SError> {
        match name {
            "read" => {
                if parameters.len() == 1 {
                    let path = parameters.pop().unwrap().owned_to_string();
                    if !path.contains(&self.pkg_format.temp_dir) {
                        return Err(SError::filesys(pid, &doc, "read", "access denied"));
                    }

                    let res = fs::read_to_string(&path);
                    return match res {
                        Ok(contents) => {
                            Ok(SVal::String(contents))
                        },
                        Err(error) => {
                            Err(SError::filesys(pid, &doc, "read", &error.to_string()))
                        }
                    };
                }
                Err(SError::filesys(pid, &doc, "read", "invalid arguments - file path not found"))
            },
            "read_blob" => {
                if parameters.len() == 1 {
                    let path = parameters.pop().unwrap().owned_to_string();
                    if !path.contains(&self.pkg_format.temp_dir) {
                        return Err(SError::filesys(pid, &doc, "read", "access denied"));
                    }
                    
                    let res = fs::read(&path);
                    return match res {
                        Ok(blob) => {
                            Ok(SVal::Blob(blob))
                        },
                        Err(error) => {
                            Err(SError::filesys(pid, &doc, "read_blob", &error.to_string()))
                        }
                    };
                }
                Err(SError::filesys(pid, &doc, "read_blob", "invalid arguments - file path not found"))
            },
            _ => {
                Err(SError::filesys(pid, &doc, "NotFound", &format!("{} is not a function in the FileSystem Library", name)))
            }
        }
    }
}
