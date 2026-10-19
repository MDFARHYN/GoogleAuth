use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        HashAlgorithm::SHA1
    }
}

impl HashAlgorithm {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "SHA256" => HashAlgorithm::SHA256,
            "SHA512" => HashAlgorithm::SHA512,
            _ => HashAlgorithm::SHA1,
        }
    }
}

/// Decode a Base32 string (RFC 4648) with or without padding, spaces, or hyphens.
pub fn decode_base32(secret: &str) -> Result<Vec<u8>, String> {
    let clean: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();

    if clean.is_empty() {
        return Err("Secret key cannot be empty".to_string());
    }

    // data-encoding RFC 4648 without padding or with padding
    if let Ok(bytes) = data_encoding::BASE32_NOPAD.decode(clean.as_bytes()) {
        return Ok(bytes);
    }
    if let Ok(bytes) = data_encoding::BASE32.decode(clean.as_bytes()) {
        return Ok(bytes);
    }

    // Try manual padding if needed
    let missing_padding = (8 - (clean.len() % 8)) % 8;
    let padded = format!("{}{}", clean, "=".repeat(missing_padding));
    data_encoding::BASE32
        .decode(padded.as_bytes())
        .map_err(|e| format!("Invalid Base32 secret: {}", e))
}

/// Compute TOTP 6-digit (or 8-digit) code for given secret, algorithm, period, and epoch seconds.
pub fn generate_totp(
    secret: &str,
    algorithm: &HashAlgorithm,
    digits: u32,
    period: u64,
    current_time: u64,
) -> Result<(String, u64, f32), String> {
    let raw_secret = decode_base32(secret)?;
    let time_step = current_time / period;
    let remaining_seconds = period - (current_time % period);
    let progress = remaining_seconds as f32 / period as f32;

    let time_bytes = time_step.to_be_bytes();

    let hash_result: Vec<u8> = match algorithm {
        HashAlgorithm::SHA1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(&raw_secret)
                .map_err(|e| format!("HMAC key error: {}", e))?;
            mac.update(&time_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::SHA256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&raw_secret)
                .map_err(|e| format!("HMAC key error: {}", e))?;
            mac.update(&time_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::SHA512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(&raw_secret)
                .map_err(|e| format!("HMAC key error: {}", e))?;
            mac.update(&time_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (hash_result.last().copied().unwrap_or(0) & 0x0F) as usize;
    if offset + 4 > hash_result.len() {
        return Err("Hash result too short for dynamic truncation".to_string());
    }

    let code_int = (((hash_result[offset] & 0x7f) as u32) << 24)
        | (((hash_result[offset + 1] as u32) & 0xff) << 16)
        | (((hash_result[offset + 2] as u32) & 0xff) << 8)
        | ((hash_result[offset + 3] as u32) & 0xff);

    let divisor = 10u32.pow(digits);
    let otp = code_int % divisor;
    let formatted_code = format!("{:0width$}", otp, width = digits as usize);

    Ok((formatted_code, remaining_seconds, progress))
}

pub fn get_current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc6238_sha1_vectors() {
        // Standard RFC 6238 secret: "12345678901234567890" in ASCII is "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" in Base32
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        // At time 59, code should be 287082
        let (code, _, _) = generate_totp(secret, &HashAlgorithm::SHA1, 6, 30, 59).unwrap();
        assert_eq!(code, "287082");

        // At time 1111111109, code should be 081804
        let (code, _, _) = generate_totp(secret, &HashAlgorithm::SHA1, 6, 30, 1111111109).unwrap();
        assert_eq!(code, "081804");
    }
}
