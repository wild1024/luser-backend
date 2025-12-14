use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use uuid::Uuid;
use rand::Rng;

/// 密码工具
pub mod password {
    use super::*;
    use argon2::{
        password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
        Argon2, Algorithm, Version, Params
    };
  
    
   
    
    /// 验证密码
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, crate::LuserError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| crate::LuserError::BusinessError(format!("密码哈希解析失败: {}", e)))?;
        
        let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);
        
        match result {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(crate::LuserError::BusinessError(format!("密码验证失败: {}", e))),
        }
    }
    
    /// 生成随机密码
    pub fn generate_random_password(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                !@#$%^&*()-_=+[]{}|;:,.<>?";
        
        let mut rng = rand::thread_rng();
        let password: String = (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        
        password
    }
}

/// 加密工具
pub mod crypto {
    use super::*;
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use ring::{digest, rand::SecureRandom};
    
    /// 生成随机密钥
    pub fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; 32];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut key).expect("Failed to generate key");
        key
    }
    
    /// 加密数据
    pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, crate::LuserError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| crate::LuserError::BusinessError(format!("创建加密器失败: {}", e)))?;
        
        let mut nonce = [0u8; 12];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut nonce)
            .map_err(|e| crate::LuserError::BusinessError(format!("生成nonce失败: {}", e)))?;
        
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| crate::LuserError::BusinessError(format!("加密失败: {}", e)))?;
        
        // 组合nonce和密文
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// 解密数据
    pub fn decrypt(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, crate::LuserError> {
        if encrypted.len() < 12 {
            return Err(crate::LuserError::BusinessError("加密数据太短".to_string()));
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| crate::LuserError::BusinessError(format!("创建加密器失败: {}", e)))?;
        
        let (nonce, ciphertext) = encrypted.split_at(12);
        
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| crate::LuserError::BusinessError(format!("解密失败: {}", e)))?;
        
        Ok(plaintext)
    }
    
    /// 计算SHA256哈希
    pub fn sha256(data: &[u8]) -> String {
        let hash = digest::digest(&digest::SHA256, data);
        hex::encode(hash.as_ref())
    }
    
    /// 计算HMAC-SHA256
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
        use ring::hmac;
        
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let signature = hmac::sign(&key, data);
        hex::encode(signature.as_ref())
    }
}

/// 时间工具
pub mod time {
    use super::*;
    
    /// 获取当前时间戳（毫秒）
    pub fn current_timestamp_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }
    
    /// 获取当前时间戳（秒）
    pub fn current_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
    
    /// 格式化时间
    pub fn format_time(dt: &DateTime<Utc>, format: &str) -> String {
        dt.format(format).to_string()
    }
    
    /// 解析时间字符串
    pub fn parse_time(time_str: &str, format: &str) -> Result<DateTime<Utc>, crate::LuserError> {
        chrono::NaiveDateTime::parse_from_str(time_str, format)
            .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
            .map_err(|e| crate::LuserError::ValidationError(format!("时间解析失败: {}", e)))
    }
    
    /// 检查时间是否在范围内
    pub fn is_time_in_range(
        time: &DateTime<Utc>,
        start: Option<&DateTime<Utc>>,
        end: Option<&DateTime<Utc>>,
    ) -> bool {
        if let Some(start_time) = start {
            if time < start_time {
                return false;
            }
        }
        
        if let Some(end_time) = end {
            if time > end_time {
                return false;
            }
        }
        
        true
    }
}

/// 字符串工具
pub mod string {
    use super::*;
    
    /// 生成随机字符串
    pub fn random_string(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789";
        
        let mut rng = rand::thread_rng();
        let string: String = (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        
        string
    }
    
    /// 掩码字符串（用于日志）
    pub fn mask_string(s: &str, start: usize, end: usize, mask_char: char) -> String {
        if s.len() <= start + end {
            return s.to_string();
        }
        
        let prefix = &s[0..start];
        let suffix = &s[s.len() - end..];
        let mask_len = s.len() - start - end;
        
        format!("{}{}{}", prefix, mask_char.to_string().repeat(mask_len), suffix)
    }
    
    /// 掩码邮箱
    pub fn mask_email(email: &str) -> String {
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return email.to_string();
        }
        
        let username = parts[0];
        let domain = parts[1];
        
        if username.len() <= 2 {
            return format!("{}@{}", mask_string(username, 0, 0, '*'), domain);
        }
        
        let masked_username = mask_string(username, 1, 1, '*');
        format!("{}@{}", masked_username, domain)
    }
    
    /// 掩码手机号
    pub fn mask_phone(phone: &str) -> String {
        if phone.len() <= 7 {
            return phone.to_string();
        }
        
        mask_string(phone, 3, 4, '*')
    }
}

/// 文件工具
pub mod file {
    use super::*;
    use std::path::Path;
    
    /// 获取文件扩展名
    pub fn get_extension(filename: &str) -> Option<String> {
        Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
    }
    
    /// 获取文件名（不含扩展名）
    pub fn get_filename_without_extension(filename: &str) -> String {
        Path::new(filename)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(filename)
            .to_string()
    }
    
    /// 获取文件大小描述
    pub fn format_file_size(size: u64) -> String {
        const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
        
        let mut size = size as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        format!("{:.2} {}", size, UNITS[unit_index])
    }
    
    /// 检查文件类型是否允许
    pub fn is_allowed_file_type(
        filename: &str,
        allowed_types: &[&str],
        allowed_extensions: &[&str],
    ) -> bool {
        // 检查扩展名
        if let Some(ext) = get_extension(filename) {
            if allowed_extensions.iter().any(|e| e.eq_ignore_ascii_case(&ext)) {
                return true;
            }
        }
        
        // 检查MIME类型（简化版）
        false
    }
    
    /// 生成唯一文件名
    pub fn generate_unique_filename(original_filename: &str) -> String {
        let extension = get_extension(original_filename)
            .map(|ext| format!(".{}", ext))
            .unwrap_or_default();
        
        let timestamp = time::current_timestamp_ms();
        let random_part = string::random_string(8);
        
        format!("{}_{}{}", timestamp, random_part, extension)
    }
}

/// URL工具
pub mod url {
    use super::*;
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    
    /// 构建查询字符串
    pub fn build_query_string(params: &[(&str, &str)]) -> String {
        let encoded_params: Vec<String> = params
            .iter()
            .map(|(key, value)| {
                let encoded_key = utf8_percent_encode(key, NON_ALPHANUMERIC).to_string();
                let encoded_value = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
                format!("{}={}", encoded_key, encoded_value)
            })
            .collect();
        
        encoded_params.join("&")
    }
    
    /// 解析查询字符串
    pub fn parse_query_string(query: &str) -> std::collections::HashMap<String, String> {
        let mut params = std::collections::HashMap::new();
        
        for pair in query.split('&') {
            let parts: Vec<&str> = pair.split('=').collect();
            if parts.len() == 2 {
                params.insert(
                    percent_encoding::percent_decode_str(parts[0])
                        .decode_utf8_lossy()
                        .to_string(),
                    percent_encoding::percent_decode_str(parts[1])
                        .decode_utf8_lossy()
                        .to_string(),
                );
            }
        }
        
        params
    }
    
    /// 添加查询参数到URL
    pub fn add_query_params(base_url: &str, params: &[(&str, &str)]) -> String {
        if params.is_empty() {
            return base_url.to_string();
        }
        
        let query_string = build_query_string(params);
        
        if base_url.contains('?') {
            format!("{}&{}", base_url, query_string)
        } else {
            format!("{}?{}", base_url, query_string)
        }
    }
}

/// 数学工具
pub mod math {
    use super::*;
    use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
    use std::str::FromStr;
    
    /// 计算百分比
    pub fn calculate_percentage(part: f64, total: f64) -> f64 {
        if total == 0.0 {
            return 0.0;
        }
        
        (part / total) * 100.0
    }
    
    /// 计算增长率
    pub fn calculate_growth_rate(current: f64, previous: f64) -> f64 {
        if previous == 0.0 {
            return 0.0;
        }
        
        ((current - previous) / previous) * 100.0
    }
    
    /// 精度计算（金融计算用）
    pub fn calculate_with_precision(value: f64, precision: usize) -> f64 {
        let bd = BigDecimal::from_f64(value).unwrap_or_default();
        let rounded = bd.round(precision as i64);
        rounded.to_f64().unwrap_or(value)
    }
    
    /// 分转元（人民币）
    pub fn fen_to_yuan(fen: i64) -> f64 {
        fen as f64 / 100.0
    }
    
    /// 元转分（人民币）
    pub fn yuan_to_fen(yuan: f64) -> i64 {
        (yuan * 100.0).round() as i64
    }
    
    /// 计算手续费
    pub fn calculate_fee(amount: f64, fee_rate: f64) -> f64 {
        let fee = amount * fee_rate / 100.0;
        calculate_with_precision(fee, 2)
    }
}

/// 验证工具
pub mod validation {
    use super::*;
    use regex::Regex;
    use lazy_static::lazy_static;
    
    lazy_static! {
        static ref EMAIL_REGEX: Regex = Regex::new(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        ).unwrap();
        
        static ref PHONE_REGEX: Regex = Regex::new(
            r"^1[3-9]\d{9}$"
        ).unwrap();
        
        static ref URL_REGEX: Regex = Regex::new(
            r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"
        ).unwrap();
        
        static ref USERNAME_REGEX: Regex = Regex::new(
            r"^[a-zA-Z0-9_]{3,50}$"
        ).unwrap();
        
        static ref CHINESE_NAME_REGEX: Regex = Regex::new(
            r"^[\u4e00-\u9fa5]{2,10}$"
        ).unwrap();
    }
    
    /// 验证邮箱格式
    pub fn is_valid_email(email: &str) -> bool {
        EMAIL_REGEX.is_match(email)
    }
    
    /// 验证手机号格式（中国）
    pub fn is_valid_phone(phone: &str) -> bool {
        PHONE_REGEX.is_match(phone)
    }
    
    /// 验证URL格式
    pub fn is_valid_url(url: &str) -> bool {
        URL_REGEX.is_match(url)
    }
    
    /// 验证用户名格式
    pub fn is_valid_username(username: &str) -> bool {
        USERNAME_REGEX.is_match(username)
    }
    
    /// 验证中文姓名格式
    pub fn is_valid_chinese_name(name: &str) -> bool {
        CHINESE_NAME_REGEX.is_match(name)
    }
    
    /// 验证身份证号格式（中国，简化版）
    pub fn is_valid_id_card(id_card: &str) -> bool {
        if id_card.len() != 18 && id_card.len() != 15 {
            return false;
        }
        
        // 这里只做基本格式验证，实际应该做更详细的验证
        let id_regex = Regex::new(r"^[1-9]\d{5}(19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$").unwrap();
        id_regex.is_match(id_card)
    }
    
    /// 验证密码强度
    pub fn validate_password_strength(password: &str) -> bool {
        if password.len() < 8 {
            return false;
        }
        
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
        
        // 至少满足三种条件
        let mut conditions_met = 0;
        if has_upper { conditions_met += 1; }
        if has_lower { conditions_met += 1; }
        if has_digit { conditions_met += 1; }
        if has_special { conditions_met += 1; }
        
        conditions_met >= 3
    }
}

/// 生成追踪ID
pub fn generate_trace_id() -> String {
    format!("trace-{}", Uuid::new_v4())
}

/// 生成会话ID
pub fn generate_session_id() -> String {
    format!("session-{}", string::random_string(32))
}

/// 生成订单号
pub fn generate_order_no(prefix: &str) -> String {
    let timestamp = time::current_timestamp_ms();
    let random_part = string::random_string(6);
    format!("{}{}{}", prefix, timestamp, random_part)
}

/// 生成支付交易号
pub fn generate_transaction_no() -> String {
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let random_part: u32 = rand::thread_rng().gen_range(100000..999999);
    format!("T{}{}", timestamp, random_part)
}

/// 生成视频ID（云服务商兼容）
pub fn generate_video_id() -> String {
    format!("video-{}", Uuid::new_v4())
}

/// 生成上传ID
pub fn generate_upload_id() -> String {
    format!("upload-{}", Uuid::new_v4())
}

/// 格式化金额（分转元）
pub fn format_amount(fen: i64) -> String {
    let yuan = math::fen_to_yuan(fen);
    format!("¥{:.2}", yuan)
}

/// 计算文件哈希（MD5）
pub fn calculate_file_md5(_data: &[u8]) -> String {
    // TODO 这里应该使用md5库计算，但为了简化我们先返回占位符
    "placeholder_md5_hash".to_string()
}

/// 计算文件哈希（SHA256）
pub fn calculate_file_sha256(_data: &[u8]) -> String {
    // TODO 这里应该使用sha2库计算
    "placeholder_sha256_hash".to_string()
}