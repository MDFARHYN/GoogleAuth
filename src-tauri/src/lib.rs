mod totp;
mod vault;
pub mod qr;
pub mod commands;

use std::sync::Arc;
use tauri::webview::{PermissionKind, PermissionResponse};
use commands::*;
use vault::VaultManager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let vault_manager = Arc::new(VaultManager::new());
    let state = AppState {
        vault: vault_manager,
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .on_permission_request(|_webview, kind| {
            match kind {
                PermissionKind::Camera => PermissionResponse::Allow,
                _ => PermissionResponse::Default,
            }
        })
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            check_vault_status,
            setup_master_password,
            unlock_vault,
            lock_vault,
            get_accounts_with_codes,
            add_manual_account,
            delete_account,
            decode_qr_image,
            import_parsed_accounts,
            export_vault_backup,
            import_vault_backup
        ])
        .run(tauri::generate_context!())
        .expect("error while running Google Authenticator desktop application");
}
