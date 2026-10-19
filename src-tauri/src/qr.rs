use std::collections::HashMap;
use std::io::Cursor;
use url::Url;
use image::GenericImageView;
use rqrr::PreparedImage;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::totp::{get_current_epoch, HashAlgorithm};
use crate::vault::Account;

#[derive(Debug, Clone)]
pub struct MigrationBatch {
    pub accounts: Vec<Account>,
    pub batch_size: u32,
    pub batch_index: u32,
}

#[derive(Debug, Clone)]
pub enum ParsedQRResult {
    Single(Account),
    Batch(MigrationBatch),
}

/// Read a Varint from byte slice, returns (value, bytes_consumed)
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in buf.iter().enumerate() {
        result |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Parse Google Authenticator Migration Protobuf payload
pub fn parse_google_migration(data_base64: &str) -> Result<MigrationBatch, String> {
    let raw_bytes = BASE64
        .decode(data_base64)
        .map_err(|e| format!("Base64 decode error on migration payload: {}", e))?;

    let mut accounts = Vec::new();
    let mut batch_size: u32 = 1;
    let mut batch_index: u32 = 0;
    let mut idx = 0;
    let len = raw_bytes.len();

    while idx < len {
        let (tag_wire, tag_len) = read_varint(&raw_bytes[idx..]).ok_or("Malformed protobuf tag")?;
        idx += tag_len;
        let field_num = tag_wire >> 3;
        let wire_type = tag_wire & 0x07;

        if field_num == 1 && wire_type == 2 {
            // repeated OtpParameters
            let (param_len, len_bytes) = read_varint(&raw_bytes[idx..]).ok_or("Malformed OtpParameters length")?;
            idx += len_bytes;
            let param_end = idx + param_len as usize;
            if param_end > len {
                return Err("OtpParameters out of bounds".to_string());
            }

            let param_slice = &raw_bytes[idx..param_end];
            idx = param_end;

            // Parse inner OtpParameters
            let mut p_idx = 0;
            let mut secret_bytes: Vec<u8> = Vec::new();
            let mut name = String::new();
            let mut issuer = String::new();
            let mut algo = HashAlgorithm::SHA1;
            let mut digits: u32 = 6;

            while p_idx < param_slice.len() {
                let (p_tag_wire, p_tag_len) = read_varint(&param_slice[p_idx..]).ok_or("Malformed inner tag")?;
                p_idx += p_tag_len;
                let p_field = p_tag_wire >> 3;
                let p_wire = p_tag_wire & 0x07;

                match (p_field, p_wire) {
                    (1, 2) => {
                        // secret
                        let (s_len, l_b) = read_varint(&param_slice[p_idx..]).ok_or("Malformed secret length")?;
                        p_idx += l_b;
                        let s_end = p_idx + s_len as usize;
                        if s_end > param_slice.len() {
                            return Err("Secret out of bounds".to_string());
                        }
                        secret_bytes = param_slice[p_idx..s_end].to_vec();
                        p_idx = s_end;
                    }
                    (2, 2) => {
                        // name
                        let (n_len, l_b) = read_varint(&param_slice[p_idx..]).ok_or("Malformed name length")?;
                        p_idx += l_b;
                        let n_end = p_idx + n_len as usize;
                        name = String::from_utf8_lossy(&param_slice[p_idx..n_end]).to_string();
                        p_idx = n_end;
                    }
                    (3, 2) => {
                        // issuer
                        let (i_len, l_b) = read_varint(&param_slice[p_idx..]).ok_or("Malformed issuer length")?;
                        p_idx += l_b;
                        let i_end = p_idx + i_len as usize;
                        issuer = String::from_utf8_lossy(&param_slice[p_idx..i_end]).to_string();
                        p_idx = i_end;
                    }
                    (4, 0) => {
                        // algorithm (1: SHA1, 2: SHA256, 3: SHA512)
                        let (algo_val, l_b) = read_varint(&param_slice[p_idx..]).ok_or("Malformed algo")?;
                        p_idx += l_b;
                        algo = match algo_val {
                            2 => HashAlgorithm::SHA256,
                            3 => HashAlgorithm::SHA512,
                            _ => HashAlgorithm::SHA1,
                        };
                    }
                    (5, 0) => {
                        // digits (1: 6 digits, 2: 8 digits)
                        let (d_val, l_b) = read_varint(&param_slice[p_idx..]).ok_or("Malformed digits")?;
                        p_idx += l_b;
                        digits = if d_val == 2 { 8 } else { 6 };
                    }
                    (_, 0) => {
                        // skip varint
                        let (_, l_b) = read_varint(&param_slice[p_idx..]).ok_or("Skip varint error")?;
                        p_idx += l_b;
                    }
                    (_, 2) => {
                        // skip length-delimited
                        let (skip_len, l_b) = read_varint(&param_slice[p_idx..]).ok_or("Skip length error")?;
                        p_idx += l_b + skip_len as usize;
                    }
                    _ => break,
                }
            }

            if !secret_bytes.is_empty() {
                let base32_secret = data_encoding::BASE32_NOPAD.encode(&secret_bytes);
                let epoch = get_current_epoch();
                let acc_id = format!("{}-{}-{}", epoch, rand::random::<u32>(), accounts.len() + 1);

                let mut final_name = name.trim().to_string();
                let mut final_issuer = issuer.trim().to_string();

                if final_name.contains(':') {
                    let parts: Vec<&str> = final_name.splitn(2, ':').collect();
                    let prefix = parts[0].trim();
                    let account_user = parts[1].trim();

                    // If issuer was empty OR prefix specifies another service (e.g. Microsoft, GitHub)
                    if final_issuer.is_empty() || (!prefix.is_empty() && !prefix.eq_ignore_ascii_case(&final_issuer)) {
                        final_issuer = prefix.to_string();
                    }
                    final_name = account_user.to_string();
                }

                if final_issuer.is_empty() {
                    final_issuer = "2FA Service".to_string();
                }
                if final_name.is_empty() {
                    final_name = "Imported Account".to_string();
                }

                accounts.push(Account {
                    id: acc_id,
                    name: final_name,
                    issuer: final_issuer,
                    secret: base32_secret,
                    algorithm: algo,
                    digits,
                    period: 30,
                    created_at: epoch,
                });
            }
        } else if wire_type == 0 {
            let (v, l_b) = read_varint(&raw_bytes[idx..]).ok_or("Skip varint error")?;
            idx += l_b;
            if field_num == 3 {
                batch_size = v as u32;
            } else if field_num == 4 {
                batch_index = v as u32;
            }
        } else if wire_type == 2 {
            let (skip_len, l_b) = read_varint(&raw_bytes[idx..]).ok_or("Skip length error")?;
            idx += l_b + skip_len as usize;
        } else {
            break;
        }
    }

    if accounts.is_empty() {
        return Err("No accounts found in migration QR code".to_string());
    }

    Ok(MigrationBatch {
        accounts,
        batch_size: if batch_size == 0 { 1 } else { batch_size },
        batch_index,
    })
}

/// Parse otpauth URI (`otpauth://totp/...` or `otpauth-migration://offline?...`)
pub fn parse_otp_uri(uri_str: &str) -> Result<ParsedQRResult, String> {
    let clean_uri = uri_str.trim();

    if clean_uri.starts_with("otpauth-migration://offline") {
        let url = Url::parse(clean_uri).map_err(|e| format!("Invalid migration URL: {}", e))?;
        let pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let data = pairs.get("data").ok_or("Missing data parameter in migration URI")?;
        let batch = parse_google_migration(data)?;
        return Ok(ParsedQRResult::Batch(batch));
    }

    if !clean_uri.starts_with("otpauth://totp/") {
        return Err("QR Code does not contain a standard otpauth:// 2FA setup link".to_string());
    }

    let url = Url::parse(clean_uri).map_err(|e| format!("Invalid URL: {}", e))?;
    let path = url.path();
    let raw_label = path.trim_start_matches('/');
    let decoded_label = percent_encoding::percent_decode_str(raw_label)
        .decode_utf8_lossy()
        .to_string();

    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let secret = query
        .get("secret")
        .ok_or("Missing secret in otpauth URL")?
        .to_string();

    let mut issuer = query.get("issuer").cloned().unwrap_or_default();
    let mut name = decoded_label.clone();

    if decoded_label.contains(':') {
        let parts: Vec<&str> = decoded_label.splitn(2, ':').collect();
        if issuer.is_empty() {
            issuer = parts[0].trim().to_string();
        }
        name = parts[1].trim().to_string();
    }

    if issuer.is_empty() {
        issuer = "Authenticator".to_string();
    }

    let algorithm = match query.get("algorithm").map(|s| s.to_uppercase()).as_deref() {
        Some("SHA256") => HashAlgorithm::SHA256,
        Some("SHA512") => HashAlgorithm::SHA512,
        _ => HashAlgorithm::SHA1,
    };

    let digits = query
        .get("digits")
        .and_then(|d| d.parse::<u32>().ok())
        .unwrap_or(6);

    let period = query
        .get("period")
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(30);

    let epoch = get_current_epoch();
    let id = format!("{}-{}", epoch, rand::random::<u32>());

    let account = Account {
        id,
        name,
        issuer,
        secret,
        algorithm,
        digits,
        period,
        created_at: epoch,
    };

    Ok(ParsedQRResult::Single(account))
}

/// Decode QR code from raw image bytes (PNG, JPEG, etc.)
pub fn decode_qr_from_bytes(image_bytes: &[u8]) -> Result<String, String> {
    let mut hints = rxing::DecodeHints::default();
    hints.TryHarder = Some(true);

    // 1. Try RXing on original buffer directly
    if let Ok(result) = rxing::helpers::detect_in_buffer_with_hints(image_bytes, Some(rxing::BarcodeFormat::QR_CODE), &mut hints) {
        return Ok(result.getText().to_string());
    }

    if let Ok(result) = rxing::helpers::detect_in_buffer_with_hints(image_bytes, None, &mut hints) {
        return Ok(result.getText().to_string());
    }

    // 2. Decode image to memory for multi-scale downsampling
    // (Crucial for photos taken close to phone screens where subpixel moire causes finder pattern detection to fail at full 1600px resolution)
    if let Ok(img) = image::load_from_memory(image_bytes)
        .or_else(|_| image::load(Cursor::new(image_bytes), image::ImageFormat::Png))
        .or_else(|_| image::load(Cursor::new(image_bytes), image::ImageFormat::Jpeg))
    {
        let (width, height) = img.dimensions();

        // Downsample passes to smooth out LCD subpixel moire patterns
        for &target_max in &[800, 1000, 600, 500] {
            if width > target_max || height > target_max {
                let resized = img.resize(target_max, target_max, image::imageops::FilterType::Lanczos3);
                let mut resize_hints = hints.clone();
                if let Ok(res) = rxing::helpers::detect_in_image_with_hints(resized, Some(rxing::BarcodeFormat::QR_CODE), &mut resize_hints) {
                    return Ok(res.getText().to_string());
                }
            }
        }

        // 3. Fallback to rqrr engine
        let mut prepared = PreparedImage::prepare_from_greyscale(
            width as usize,
            height as usize,
            |x, y| {
                let pixel = img.get_pixel(x as u32, y as u32);
                (0.299 * pixel[0] as f32 + 0.587 * pixel[1] as f32 + 0.114 * pixel[2] as f32) as u8
            },
        );

        let grids = prepared.detect_grids();
        for grid in grids {
            if let Ok((_meta, content)) = grid.decode() {
                return Ok(content);
            }
        }
    }

    Err("Could not decode QR code. Please make sure the QR code is clearly visible, focused, and well-lit.".to_string())
}
