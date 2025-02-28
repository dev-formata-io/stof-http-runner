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

use stof::{SDoc, SVal};


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

// By default, the runner is unprotected
type Admin {
    username: str = 'admin'
    password: str = ''

    // permissions granted to any unauthenticated user
    unauth_perms: int = 0b000;
}

type Runner {
    #[schema]
    server: Server = new Server {};
    
    #[schema]
    registry: Registry = new Registry {};

    #[schema]
    admin: Admin = new Admin {};

    #[run]
    fn run() {
        self.valid = self.schemafy(self);
    }
}

fn unauth_read(): bool { return root.admin.unauth_perms & 0b001 > 0; }
fn unauth_modify(): bool { return root.admin.unauth_perms & 0b010 > 0; }
fn unauth_exec(): bool { return root.admin.unauth_perms & 0b100 > 0; }

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


/// Users file name.
const USERS_FILE_NAME: &str = "__users__.json";
const USERS_INTERFACE: &str = r#"
// make sure the Users root exists
root Users: {}

type User {
    username: str;

    #[private]
    password: str;

    // yes or no to: execute stof, modify registry, read registry
    // 0 is no permissions or the same as unauthenticated
    perms: int = 0b000;

    // modify scope
    // if set, this user can only modify this registry within this scope
    scope: str = '';

    fn authenticated(password: str): bool {
        return self.password == password;
    }
    fn can_read_registry(): bool {
        return self.perms & 0b001 > 0;
    }
    fn can_modify_registry(): bool {
        return self.perms & 0b010 > 0;
    }
    fn can_modify_scope(path: str): bool {
        let user_scope = self.scope;
        if (user_scope.len() < 1) return true;

        let scope = path.split('/').first();
        if (scope.startsWith('@')) scope = scope.substring(1);
        return scope == user_scope;
    }
    fn can_exec(): bool {
        return self.perms & 0b100 > 0;
    }
}

obj Admin: {
    // set a user
    fn set_user(username: str, password: str, perms: int = 0b111, scope: str = ''): bool {
        Users.removeField(username, true);
        return Users.set(username, new User {
            username: username,
            password: password,
            perms: perms,
            scope: scope,
        });
    }

    // delete a user by username
    fn delete_user(username: str): bool {
        return Users.removeField(username, true);
    }

    // export users to a json file
    fn export_json_users(path: str) {
        let json = stringify(Users, 'json');
        fs.write(path, json);
    }
}

// authenticate a user by username, returning the user if present
fn authenticate(username: str, password: str): User {
    let user: User = Users.at(username);
    if (user && user.authenticated(password)) {
        return user;
    }
    return null;
}

// can this user read the registry?
fn can_read_registry(username: str, password: str): bool {
    let user = self.authenticate(username, password);
    return user && user.can_read_registry();
}

// can this user modify the registry?
fn can_modify_registry(username: str, password: str, path: str = ''): bool {
    let user = self.authenticate(username, password);
    return user && user.can_modify_registry() && (path.len() < 1 || user.can_modify_scope(path));
}

// can this user exec on the server?
fn can_exec(username: str, password: str): bool {
    let user = self.authenticate(username, password);
    return user && user.can_exec();
}
"#;


/// Get admin (if defined).
/// Returns admin username & password if the configuration contains an admin definition (both username and non-empty password).
pub(crate) fn get_admin(config: &SDoc) -> Option<(String, String)> {
    if let Some(username) = config.field("root.admin.username", None) {
        if let Some(password) = config.field("root.admin.password", None) {
            let user = username.to_string();
            let pass = password.to_string();
            if user.len() > 0 && pass.len() > 0 {
                return Some((user, pass));
            }
        }
    }
    None
}


/// Load the stof users document.
pub(crate) fn load_users(config: &SDoc) -> (String, SDoc) {
    let mut registry_path = String::from("registry");
    if let Some(field) = config.field("root.registry.path", None) {
        registry_path = field.to_string();
    }
    let users_file_path = format!("{}/{}", registry_path, USERS_FILE_NAME);

    let mut doc = SDoc::default();
    let _ = doc.file_import("main", "json", &users_file_path, "json", "Users");
    let _ = doc.string_import("main", "stof", USERS_INTERFACE, "");

    (users_file_path, doc)
}


/// ADMIN save users.
pub(crate) fn admin_export_users(pair: &mut (String, SDoc)) {
    let path = SVal::from(&pair.0);
    let _ = pair.1.call_func("root.Admin.export_json_users", None, vec![path]);
}


/// ADMIN create a new user.
pub(crate) fn admin_set_user(pair: &mut (String, SDoc), user: &str, pass: &str, perms: i64, scope: &str) -> bool {
    if let Ok(res) = pair.1.call_func("root.Admin.set_user", None, vec![user.into(), pass.into(), perms.into(), scope.into()]) {
        admin_export_users(pair);
        return res.truthy();
    }
    false
}


/// ADMIN delete a user.
pub(crate) fn admin_delete_user(pair: &mut (String, SDoc), user: &str) -> bool {
    if let Ok(res) = pair.1.call_func("root.Admin.delete_user", None, vec![user.into()]) {
        admin_export_users(pair);
        return res.truthy();
    }
    false
}


/// Can read registry?
pub(crate) fn can_read_registry(pair: &mut (String, SDoc), user: &str, pass: &str) -> bool {
    if let Ok(res) = pair.1.call_func("root.can_read_registry", None, vec![user.into(), pass.into()]) {
        return res.truthy();
    }
    false
}


/// Can modify registry?
pub(crate) fn can_modify_registry(pair: &mut (String, SDoc), user: &str, pass: &str, path: &str) -> bool {
    if let Ok(res) = pair.1.call_func("root.can_modify_registry", None, vec![user.into(), pass.into(), path.into()]) {
        return res.truthy();
    }
    false
}


/// Can exec?
pub(crate) fn can_exec(pair: &mut (String, SDoc), user: &str, pass: &str) -> bool {
    if let Ok(res) = pair.1.call_func("root.can_exec", None, vec![user.into(), pass.into()]) {
        return res.truthy();
    }
    false
}
