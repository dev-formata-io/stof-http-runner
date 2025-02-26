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

use stof::SDoc;


/// Stof Types for Config file.
const STOF_TYPES: &str = r#"
type Server {
    #[schema((value: int): bool => value > 0 && value < 10000)]
    port: int = 3030;

    #[schema((value: vec): bool => value.len() >= 4)]
    address: vec = [127, 0, 0, 1];

    // Show Stof errors in responses?
    // Set to false to return opaque errors instead.
    errors: bool = true;

    // Can execute stof?
    run_stof: bool = true;

    // Run timeout.
    run_timeout: s = 10s;
    fn timeout(): s {
        return self.run_timeout;
    }
}

type Registry {
    // Can this runner store stof interfaces?
    enabled: bool = true;

    #[schema((value: str): bool => value.len() > 0)]
    path: str = 'registry';
}

type Runner {
    #[schema]
    server: Server = new Server {};
    
    #[schema]
    registry: Registry = new Registry {};

    #[run]
    fn run() {
        self.valid = self.schemafy(self);
    }
}

#[init]
fn init() {
    root as Runner;
    root.exec();
    if (root.debug) pln(root);
}
"#;


/// Create the Stof configuration document.
pub fn load_config(file: Option<String>) -> Result<SDoc, String> {
    let mut doc;
    if let Some(file) = file {
        if let Ok(loaded) = SDoc::file(&file, "stof") {
            doc = loaded;
        } else {
            return Err(format!("'{}' does not exist", file));
        }
    } else {
        doc = SDoc::default();
    }

    let res = doc.string_import("main", "stof", STOF_TYPES, "");
    if res.is_err() {
        return Err(format!("error loading configuration types"));
    }
    if let Some(valid) = doc.get("root.valid", None) {
        if !valid.truthy() {
            return Err(format!("not a valid configuration"));
        }
    } else {
        return Err(format!("not a valid configuration"));
    }

    Ok(doc)
}
