use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    Algorithm, Argon2, Params, Version,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::totp::HashAlgorithm;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub secret: String,
    pub algorithm: HashAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub version: u32,
    pub accounts: Vec<Account>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedVaultDisk {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

pub struct VaultManager {
    file_path: PathBuf,
    // Active unlocked state
    active_key: Mutex<Option<[u8; 32]>>,
    cached_data: Mutex<Option<VaultData>>,
}

impl VaultManager {
    pub fn new() -> Self {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("GoogleAuth");
        if !path.exists() {
            let _ = fs::create_dir_all(&path);
        }
        path.push("vault.enc");

        Self {
            file_path: path,
            active_key: Mutex::new(None),
            cached_data: Mutex::new(None),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.file_path.exists()
    }

    pub fn is_unlocked(&self) -> bool {
        self.active_key.lock().unwrap().is_some()
    }

    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
        let params = Params::new(19456, 2, 1, Some(32))
            .map_err(|e| format!("Argon2 params error: {}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| format!("Argon2 hashing error: {}", e))?;

        Ok(key)
    }

    pub fn setup_master_password(&self, password: &str) -> Result<(), String> {
        if password.len() < 4 {
            return Err("Password must be at least 4 characters".to_string());
        }

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let key = Self::derive_key(password, &salt)?;

        let initial_data = VaultData {
            version: 1,
            accounts: Vec::new(),
        };

        self.save_encrypted(&key, &salt, &initial_data)?;

        // Set active in memory
        *self.active_key.lock().unwrap() = Some(key);
        *self.cached_data.lock().unwrap() = Some(initial_data);

        Ok(())
    }

    pub fn unlock(&self, password: &str) -> Result<(), String> {
        if !self.file_path.exists() {
            return Err("Vault has not been created yet".to_string());
        }

        let raw_file = fs::read(&self.file_path)
            .map_err(|e| format!("Failed to read vault file: {}", e))?;

        let disk_data: EncryptedVaultDisk = serde_json::from_slice(&raw_file)
            .map_err(|e| format!("Corrupted vault file format: {}", e))?;

        let key = Self::derive_key(password, &disk_data.salt)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| format!("Invalid key length: {}", e))?;

        if disk_data.nonce.len() != 12 {
            return Err("Invalid nonce length in vault file".to_string());
        }
        let nonce = Nonce::from_slice(&disk_data.nonce);

        let plaintext = cipher
            .decrypt(nonce, disk_data.ciphertext.as_ref())
            .map_err(|_| "Incorrect master password. Access denied.".to_string())?;

        let vault_data: VaultData = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Failed to parse vault contents: {}", e))?;

        *self.active_key.lock().unwrap() = Some(key);
        *self.cached_data.lock().unwrap() = Some(vault_data);

        Ok(())
    }

    pub fn lock(&self) {
        *self.active_key.lock().unwrap() = None;
        *self.cached_data.lock().unwrap() = None;
    }

    fn save_encrypted(
        &self,
        key: &[u8; 32],
        salt: &[u8],
        data: &VaultData,
    ) -> Result<(), String> {
        let plaintext = serde_json::to_vec(data)
            .map_err(|e| format!("Serialization error: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("Key init error: {}", e))?;

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        let disk_data = EncryptedVaultDisk {
            salt: salt.to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };

        let raw_bytes = serde_json::to_vec_pretty(&disk_data)
            .map_err(|e| format!("Disk serialization error: {}", e))?;

        if let Some(parent) = self.file_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        fs::write(&self.file_path, raw_bytes)
            .map_err(|e| format!("Failed to write to disk: {}", e))?;

        Ok(())
    }

    fn persist_current_data(&self) -> Result<(), String> {
        let key_guard = self.active_key.lock().unwrap();
        let key = key_guard.as_ref().ok_or("Vault is locked")?;

        let data_guard = self.cached_data.lock().unwrap();
        let data = data_guard.as_ref().ok_or("Vault data unavailable")?;

        // Extract existing salt or generate new
        let salt = if self.file_path.exists() {
            if let Ok(raw) = fs::read(&self.file_path) {
                if let Ok(disk) = serde_json::from_slice::<EncryptedVaultDisk>(&raw) {
                    disk.salt
                } else {
                    let mut s = vec![0u8; 16];
                    OsRng.fill_bytes(&mut s);
                    s
                }
            } else {
                let mut s = vec![0u8; 16];
                OsRng.fill_bytes(&mut s);
                s
            }
        } else {
            let mut s = vec![0u8; 16];
            OsRng.fill_bytes(&mut s);
            s
        };

        self.save_encrypted(key, &salt, data)
    }

    pub fn clean_name(issuer: &str, name: &str) -> String {
        let clean = name.trim();
        if let Some((prefix, rest)) = clean.split_once(':') {
            if prefix.trim().eq_ignore_ascii_case(issuer.trim()) || prefix.trim().eq_ignore_ascii_case("Google") {
                return rest.trim().to_string();
            }
        }
        clean.to_string()
    }

    pub fn normalize_account_name(issuer: &str, name: &str) -> String {
        Self::clean_name(issuer, name).to_lowercase()
    }

    pub fn is_same_account(a: &Account, b: &Account) -> bool {
        // 1. Same 2FA secret key -> identical credential
        if a.secret == b.secret {
            return true;
        }

        // 2. Same provider and same email address
        let clean_issuer_a = a.issuer.trim().to_lowercase();
        let clean_issuer_b = b.issuer.trim().to_lowercase();
        if clean_issuer_a == clean_issuer_b && !clean_issuer_a.is_empty() {
            let norm_a = Self::normalize_account_name(&a.issuer, &a.name);
            let norm_b = Self::normalize_account_name(&b.issuer, &b.name);
            if norm_a == norm_b && !norm_a.is_empty() {
                return true;
            }
        }

        false
    }

    pub fn cleanup_duplicates(&self) -> Result<(), String> {
        let mut changed = false;
        {
            let mut guard = self.cached_data.lock().unwrap();
            let data = guard.as_mut().ok_or("Vault is locked")?;
            let mut deduped: Vec<Account> = Vec::new();
            for mut acc in data.accounts.drain(..) {
                acc.name = Self::clean_name(&acc.issuer, &acc.name);
                if let Some(existing) = deduped.iter_mut().find(|a| Self::is_same_account(a, &acc)) {
                    // Duplicate found: keep the cleaner name and preserve existing ID
                    let existing_id = existing.id.clone();
                    *existing = acc;
                    existing.id = existing_id;
                    changed = true;
                } else {
                    deduped.push(acc);
                }
            }
            data.accounts = deduped;
        }
        if changed {
            let _ = self.persist_current_data();
        }
        Ok(())
    }

    pub fn get_accounts(&self) -> Result<Vec<Account>, String> {
        let _ = self.cleanup_duplicates();
        let guard = self.cached_data.lock().unwrap();
        match guard.as_ref() {
            Some(data) => Ok(data.accounts.clone()),
            None => Err("Vault is locked".to_string()),
        }
    }

    pub fn add_account(&self, mut account: Account) -> Result<(), String> {
        account.name = Self::clean_name(&account.issuer, &account.name);
        {
            let mut guard = self.cached_data.lock().unwrap();
            let data = guard.as_mut().ok_or("Vault is locked")?;
            // If account with same provider+email or secret already exists, replace it
            if let Some(existing) = data.accounts.iter_mut().find(|a| a.id == account.id || Self::is_same_account(a, &account)) {
                let existing_id = existing.id.clone();
                *existing = account;
                existing.id = existing_id;
            } else {
                data.accounts.push(account);
            }
        }
        self.persist_current_data()
    }

    pub fn add_batch_accounts(&self, new_accounts: Vec<Account>) -> Result<usize, String> {
        let mut count = 0;
        {
            let mut guard = self.cached_data.lock().unwrap();
            let data = guard.as_mut().ok_or("Vault is locked")?;
            for mut acc in new_accounts {
                acc.name = Self::clean_name(&acc.issuer, &acc.name);
                if let Some(existing) = data.accounts.iter_mut().find(|a| Self::is_same_account(a, &acc)) {
                    // Replace existing account with updated one, keeping ID
                    let existing_id = existing.id.clone();
                    *existing = acc;
                    existing.id = existing_id;
                } else {
                    data.accounts.push(acc);
                    count += 1;
                }
            }
        }
        self.persist_current_data()?;
        Ok(count)
    }

    pub fn delete_account(&self, id: &str) -> Result<(), String> {
        {
            let mut guard = self.cached_data.lock().unwrap();
            let data = guard.as_mut().ok_or("Vault is locked")?;
            data.accounts.retain(|a| a.id != id);
        }
        self.persist_current_data()
    }
}
