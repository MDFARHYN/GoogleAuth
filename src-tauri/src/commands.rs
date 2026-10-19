use std::sync::Arc;
use serde::Serialize;
use tauri::State;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::totp::{decode_base32, generate_totp, get_current_epoch, HashAlgorithm};
use crate::vault::{Account, VaultManager};
use crate::qr::{decode_qr_from_bytes, parse_otp_uri, ParsedQRResult};

pub struct AppState {
    pub vault: Arc<VaultManager>,
}

#[derive(Serialize)]
pub struct VaultStatusResponse {
    pub is_initialized: bool,
    pub is_unlocked: bool,
}

#[derive(Serialize)]
pub struct AccountWithCode {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub secret_masked: String,
    pub code: String,
    pub remaining_seconds: u64,
    pub progress: f32,
    pub period: u64,
    pub digits: u32,
}

#[derive(Serialize)]
pub struct QRScanResponse {
    pub mode: String, // "single" or "batch"
    pub count: usize,
    pub accounts: Vec<Account>,
    pub batch_size: u32,
    pub batch_index: u32,
    pub message: String,
}

#[tauri::command]
pub fn check_vault_status(state: State<'_, AppState>) -> VaultStatusResponse {
    VaultStatusResponse {
        is_initialized: state.vault.is_initialized(),
        is_unlocked: state.vault.is_unlocked(),
    }
}

#[tauri::command]
pub fn setup_master_password(state: State<'_, AppState>, password: String) -> Result<String, String> {
    state.vault.setup_master_password(&password)?;
    Ok("Master password configured successfully".to_string())
}

#[tauri::command]
pub fn unlock_vault(state: State<'_, AppState>, password: String) -> Result<String, String> {
    state.vault.unlock(&password)?;
    Ok("Vault unlocked".to_string())
}

#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) -> Result<String, String> {
    state.vault.lock();
    Ok("Vault locked".to_string())
}

#[tauri::command]
pub fn get_accounts_with_codes(state: State<'_, AppState>) -> Result<Vec<AccountWithCode>, String> {
    let accounts = state.vault.get_accounts()?;
    let now = get_current_epoch();
    let mut results = Vec::new();

    for acc in accounts {
        let (raw_code, remaining, progress) = generate_totp(
            &acc.secret,
            &acc.algorithm,
            acc.digits,
            acc.period,
            now,
        ).unwrap_or_else(|_| ("------".to_string(), 0, 0.0));

        // Format 6-digit with space: "123 456"
        let formatted_code = if raw_code.len() == 6 {
            format!("{} {}", &raw_code[0..3], &raw_code[3..6])
        } else {
            raw_code
        };

        // Mask secret for display
        let secret_masked = if acc.secret.len() > 8 {
            format!("{}...{}", &acc.secret[..4], &acc.secret[acc.secret.len() - 4..])
        } else {
            "********".to_string()
        };

        results.push(AccountWithCode {
            id: acc.id,
            name: acc.name,
            issuer: acc.issuer,
            secret_masked,
            code: formatted_code,
            remaining_seconds: remaining,
            progress,
            period: acc.period,
            digits: acc.digits,
        });
    }

    Ok(results)
}

#[tauri::command]
pub fn add_manual_account(
    state: State<'_, AppState>,
    name: String,
    issuer: String,
    secret: String,
    algorithm: Option<String>,
    digits: Option<u32>,
    period: Option<u64>,
) -> Result<Account, String> {
    let clean_secret = secret.trim().to_uppercase();
    // Validate base32
    decode_base32(&clean_secret)?;

    let algo = match algorithm.as_deref() {
        Some(a) => HashAlgorithm::from_str(a),
        None => HashAlgorithm::SHA1,
    };

    let epoch = get_current_epoch();
    let acc = Account {
        id: format!("{}-{}", epoch, rand::random::<u32>()),
        name: if name.trim().is_empty() { "Manual Account".to_string() } else { name.trim().to_string() },
        issuer: if issuer.trim().is_empty() { "2FA Service".to_string() } else { issuer.trim().to_string() },
        secret: clean_secret,
        algorithm: algo,
        digits: digits.unwrap_or(6),
        period: period.unwrap_or(30),
        created_at: epoch,
    };

    state.vault.add_account(acc.clone())?;
    Ok(acc)
}

#[tauri::command]
pub fn delete_account(state: State<'_, AppState>, id: String) -> Result<String, String> {
    state.vault.delete_account(&id)?;
    Ok("Account deleted".to_string())
}

#[tauri::command]
pub fn decode_qr_image(image_base64: String) -> Result<QRScanResponse, String> {
    let clean_str = image_base64.trim();

    // If passed a raw otpauth URI directly, parse it immediately
    if clean_str.starts_with("otpauth://") || clean_str.starts_with("otpauth-migration://") {
        let parsed = parse_otp_uri(clean_str)?;
        return match parsed {
            ParsedQRResult::Single(acc) => Ok(QRScanResponse {
                mode: "single".to_string(),
                count: 1,
                accounts: vec![acc],
                batch_size: 1,
                batch_index: 0,
                message: "Single 2FA account detected successfully".to_string(),
            }),
            ParsedQRResult::Batch(batch) => {
                let count = batch.accounts.len();
                Ok(QRScanResponse {
                    mode: "batch".to_string(),
                    count,
                    accounts: batch.accounts,
                    batch_size: batch.batch_size,
                    batch_index: batch.batch_index,
                    message: format!("Google Authenticator export detected! {} accounts found.", count),
                })
            }
        };
    }

    // Strip data:image/...;base64, prefix if present
    let clean_base64 = if let Some(idx) = clean_str.find(',') {
        &clean_str[idx + 1..]
    } else {
        clean_str
    };

    let bytes = BASE64
        .decode(clean_base64.trim())
        .map_err(|e| format!("Invalid base64 image data: {}", e))?;

    let decoded_text = decode_qr_from_bytes(&bytes)?;

    let parsed = parse_otp_uri(&decoded_text)?;

    match parsed {
        ParsedQRResult::Single(acc) => Ok(QRScanResponse {
            mode: "single".to_string(),
            count: 1,
            accounts: vec![acc],
            batch_size: 1,
            batch_index: 0,
            message: "Single 2FA account detected successfully".to_string(),
        }),
        ParsedQRResult::Batch(batch) => {
            let count = batch.accounts.len();
            Ok(QRScanResponse {
                mode: "batch".to_string(),
                count,
                accounts: batch.accounts,
                batch_size: batch.batch_size,
                batch_index: batch.batch_index,
                message: format!("Google Authenticator export detected! {} accounts found.", count),
            })
        }
    }
}

#[tauri::command]
pub fn import_parsed_accounts(
    state: State<'_, AppState>,
    accounts: Vec<Account>,
) -> Result<usize, String> {
    state.vault.add_batch_accounts(accounts)
}

#[tauri::command]
pub fn export_vault_backup(state: State<'_, AppState>) -> Result<String, String> {
    let accounts = state.vault.get_accounts()?;
    serde_json::to_string_pretty(&accounts)
        .map_err(|e| format!("Export serialization failed: {}", e))
}

#[tauri::command]
pub fn import_vault_backup(state: State<'_, AppState>, json_str: String) -> Result<usize, String> {
    let accounts: Vec<Account> = serde_json::from_str(&json_str)
        .map_err(|e| format!("Invalid backup JSON: {}", e))?;
    state.vault.add_batch_accounts(accounts)
}
