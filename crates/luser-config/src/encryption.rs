use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use parking_lot::RwLock;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, instrument, warn};

use crate::{
    ConfigError, ConfigResult, ConfigSecurityLevel, ENCRYPTION_KEY_ENV, ENCRYPTION_PREFIX,
    ENCRYPTION_SUFFIX,
};
use base64::{Engine, engine::general_purpose::STANDARD};

/// 加密算法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl EncryptionAlgorithm {
    /// 从字符串解析算法
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "aes-256-gcm" | "aes_gcm" | "aes" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" | "chacha20" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// 获取密钥长度（字节）
    pub fn key_length(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
        }
    }

    /// 获取Nonce长度（字节）
    pub fn nonce_length(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::ChaCha20Poly1305 => 12,
        }
    }

    /// 获取标签长度（字节）
    pub fn tag_length(&self) -> usize {
        match self {
            Self::Aes256Gcm => 16,
            Self::ChaCha20Poly1305 => 16,
        }
    }
}

/// 加密管理器
#[derive(Debug, Clone)]
pub struct EncryptionManager {
    algorithm: EncryptionAlgorithm,
    key: Arc<RwLock<Vec<u8>>>,
    nonce_generator: Arc<dyn NonceGenerator>,
}

/// Nonce生成器
pub trait NonceGenerator: std::fmt::Debug + Send + Sync {
    /// 生成Nonce
    fn generate_nonce(&self, length: usize) -> Vec<u8>;
}

/// 安全的Nonce生成器
#[derive(Debug)]
pub struct SecureNonceGenerator;

impl NonceGenerator for SecureNonceGenerator {
    fn generate_nonce(&self, length: usize) -> Vec<u8> {
        let mut nonce = vec![0u8; length];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut nonce).expect("Failed to generate nonce");
        nonce
    }
}

/// 时间戳Nonce生成器
#[derive(Debug)]
pub struct TimestampNonceGenerator;

impl NonceGenerator for TimestampNonceGenerator {
    fn generate_nonce(&self, length: usize) -> Vec<u8> {
        let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let mut nonce = vec![0u8; length];
        let bytes = timestamp.to_le_bytes();
        let copy_len = std::cmp::min(length, bytes.len());
        nonce[..copy_len].copy_from_slice(&bytes[..copy_len]);
        nonce
    }
}

impl EncryptionManager {
    /// 创建新的加密管理器
    pub fn new(algorithm: EncryptionAlgorithm, key: Vec<u8>) -> ConfigResult<Self> {
        // 验证密钥长度
        if key.len() != algorithm.key_length() {
            return Err(ConfigError::EncryptionError(format!(
                "Invalid key length: expected {}, got {}",
                algorithm.key_length(),
                key.len()
            )));
        }

        Ok(Self {
            algorithm,
            key: Arc::new(RwLock::new(key)),
            nonce_generator: Arc::new(SecureNonceGenerator),
        })
    }

    /// 从base64编码的密钥创建加密管理器
    pub fn from_base64_key(algorithm: EncryptionAlgorithm, base64_key: &str) -> ConfigResult<Self> {
        let key = STANDARD.decode(base64_key).map_err(|e| {
            ConfigError::EncryptionError(format!("Failed to decode base64 key: {}", e))
        })?;

        Self::new(algorithm, key)
    }

    /// 从环境变量创建加密管理器
    pub fn from_env(algorithm: EncryptionAlgorithm, env_var: &str) -> ConfigResult<Self> {
        let base64_key = std::env::var(env_var).map_err(|e| {
            ConfigError::EnvError(format!("Failed to read env var {}: {}", env_var, e))
        })?;

        Self::from_base64_key(algorithm, &base64_key)
    }

    /// 生成随机密钥
    pub fn generate_key(algorithm: EncryptionAlgorithm) -> ConfigResult<Vec<u8>> {
        let length = algorithm.key_length();
        let mut key = vec![0u8; length];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut key)
            .map_err(|e| ConfigError::EncryptionError(format!("Failed to generate key: {}", e)))?;

        Ok(key)
    }

    /// 生成随机密钥（base64编码）
    pub fn generate_base64_key(algorithm: EncryptionAlgorithm) -> ConfigResult<String> {
        let key = Self::generate_key(algorithm)?;
        Ok(STANDARD.encode(&key))
    }

    /// 加密数据
    #[instrument(skip(self, plaintext))]
    pub fn encrypt(&self, plaintext: &[u8]) -> ConfigResult<Vec<u8>> {
        let key = self.key.read();

        match self.algorithm {
            EncryptionAlgorithm::Aes256Gcm => self.encrypt_aes_gcm(&key, plaintext),
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.encrypt_chacha20_poly1305(&key, plaintext)
            }
        }
    }

    /// 加密字符串
    pub fn encrypt_string(&self, plaintext: &str) -> ConfigResult<String> {
        let ciphertext = self.encrypt(plaintext.as_bytes())?;
        Ok(STANDARD.encode(&ciphertext))
    }

    /// 解密数据
    #[instrument(skip(self, ciphertext))]
    pub fn decrypt(&self, ciphertext: &[u8]) -> ConfigResult<Vec<u8>> {
        let key = self.key.read();

        match self.algorithm {
            EncryptionAlgorithm::Aes256Gcm => self.decrypt_aes_gcm(&key, ciphertext),
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.decrypt_chacha20_poly1305(&key, ciphertext)
            }
        }
    }

    /// 解密字符串
    pub fn decrypt_string(&self, ciphertext: &str) -> ConfigResult<String> {
        let ciphertext_bytes = STANDARD.decode(ciphertext).map_err(|e| {
            ConfigError::EncryptionError(format!("Failed to decode base64 ciphertext: {}", e))
        })?;

        let plaintext = self.decrypt(&ciphertext_bytes)?;
        String::from_utf8(plaintext).map_err(|e| {
            ConfigError::EncryptionError(format!(
                "Failed to convert decrypted data to string: {}",
                e
            ))
        })
    }

    /// 轮换密钥
    pub fn rotate_key(&self, new_key: Vec<u8>) -> ConfigResult<()> {
        if new_key.len() != self.algorithm.key_length() {
            return Err(ConfigError::EncryptionError(format!(
                "Invalid key length: expected {}, got {}",
                self.algorithm.key_length(),
                new_key.len()
            )));
        }

        *self.key.write() = new_key;
        info!("Encryption key rotated successfully");

        Ok(())
    }

    /// 获取当前密钥（base64编码）
    pub fn get_base64_key(&self) -> String {
        let key = self.key.read();
        STANDARD.encode(&*key)
    }

    /// 获取算法
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// AES-GCM加密
    fn encrypt_aes_gcm(&self, key: &[u8], plaintext: &[u8]) -> ConfigResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| ConfigError::EncryptionError(format!("Failed to create cipher: {}", e)))?;

        let nonce_bytes = self
            .nonce_generator
            .generate_nonce(self.algorithm.nonce_length());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ConfigError::EncryptionError(format!("Failed to encrypt: {}", e)))?;

        // 组合nonce和密文
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// AES-GCM解密
    fn decrypt_aes_gcm(&self, key: &[u8], ciphertext: &[u8]) -> ConfigResult<Vec<u8>> {
        let nonce_length = self.algorithm.nonce_length();

        if ciphertext.len() < nonce_length {
            return Err(ConfigError::EncryptionError(format!(
                "Ciphertext too short: expected at least {}, got {}",
                nonce_length,
                ciphertext.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| ConfigError::EncryptionError(format!("Failed to create cipher: {}", e)))?;

        let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(nonce_length);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|e| ConfigError::DecryptionError(format!("Failed to decrypt: {}", e)))?;

        Ok(plaintext)
    }

    /// ChaCha20-Poly1305加密
    fn encrypt_chacha20_poly1305(&self, key: &[u8], plaintext: &[u8]) -> ConfigResult<Vec<u8>> {
        // 注意：这里使用AES-GCM作为替代，实际项目中应该实现ChaCha20-Poly1305
        // 由于依赖库限制，这里使用AES-GCM
        warn!("ChaCha20-Poly1305 not implemented, using AES-GCM instead");
        self.encrypt_aes_gcm(key, plaintext)
    }

    /// ChaCha20-Poly1305解密
    fn decrypt_chacha20_poly1305(&self, key: &[u8], ciphertext: &[u8]) -> ConfigResult<Vec<u8>> {
        // 注意：这里使用AES-GCM作为替代，实际项目中应该实现ChaCha20-Poly1305
        warn!("ChaCha20-Poly1305 not implemented, using AES-GCM instead");
        self.decrypt_aes_gcm(key, ciphertext)
    }

    /// 检查数据是否已加密
    pub fn is_encrypted(&self, data: &str) -> bool {
        if let Ok(bytes) = STANDARD.decode(data) {
            // 检查长度是否足够包含nonce
            bytes.len() >= self.algorithm.nonce_length()
        } else {
            false
        }
    }

    /// 计算数据的哈希值
    pub fn hash_data(&self, data: &[u8]) -> ConfigResult<String> {
        use ring::digest;

        let hash = digest::digest(&digest::SHA256, data);
        Ok(hex::encode(hash.as_ref()))
    }

    /// 验证数据完整性
    pub fn verify_integrity(&self, data: &[u8], expected_hash: &str) -> ConfigResult<bool> {
        let actual_hash = self.hash_data(data)?;
        Ok(actual_hash == expected_hash)
    }
}

/// 配置加密器
#[derive(Debug, Clone)]
pub struct ConfigEncryptor {
    encryption_manager: Arc<EncryptionManager>,
    security_levels: Arc<RwLock<Vec<ConfigSecurityLevel>>>,
}

impl ConfigEncryptor {
    /// 创建新的配置加密器
    pub fn new(encryption_manager: EncryptionManager) -> Self {
        Self {
            encryption_manager: Arc::new(encryption_manager),
            security_levels: Arc::new(RwLock::new(vec![
                ConfigSecurityLevel::Sensitive,
                ConfigSecurityLevel::Secret,
            ])),
        }
    }

    /// 加密配置值
    pub fn encrypt_config_value(
        &self,
        key: &str,
        value: &str,
        security_level: ConfigSecurityLevel,
    ) -> ConfigResult<String> {
        if !self.should_encrypt(security_level) {
            return Ok(value.to_string());
        }

        info!("Encrypting config value for key: {}", key);

        let encrypted = self.encryption_manager.encrypt_string(value)?;

        // 添加安全级别标记
        let marked = format!("ENC[{}:{}]", security_level.name(), encrypted);

        Ok(marked)
    }

    /// 解密配置值
    pub fn decrypt_config_value(&self, key: &str, value: &str) -> ConfigResult<String> {
        if !self.is_encrypted_value(value) {
            return Ok(value.to_string());
        }

        info!("Decrypting config value for key: {}", key);

        // 解析标记的加密值
        let (security_level, encrypted_value) = self.parse_encrypted_value(value)?;

        if !self.should_decrypt(security_level) {
            return Ok(value.to_string());
        }

        self.encryption_manager.decrypt_string(&encrypted_value)
    }

    /// 批量加密配置值
    pub fn encrypt_config_values(
        &self,
        values: &[(&str, &str, ConfigSecurityLevel)],
    ) -> ConfigResult<Vec<(String, String)>> {
        let mut results = Vec::with_capacity(values.len());

        for (key, value, security_level) in values {
            let encrypted = self.encrypt_config_value(key, value, *security_level)?;
            results.push((key.to_string(), encrypted));
        }

        Ok(results)
    }

    /// 批量解密配置值
    pub fn decrypt_config_values(
        &self,
        values: &[(&str, &str)],
    ) -> ConfigResult<Vec<(String, String)>> {
        let mut results = Vec::with_capacity(values.len());

        for (key, value) in values {
            let decrypted = self.decrypt_config_value(key, value)?;
            results.push((key.to_string(), decrypted));
        }

        Ok(results)
    }

    /// 加密整个配置
    pub fn encrypt_config(&self, config: &mut crate::AppConfig) -> ConfigResult<()> {
        info!("Encrypting configuration");

        // 1. 加密数据库配置中的敏感信息
        self.encrypt_database_config(&mut config.database)?;

        // 2. 加密Redis密码
        self.encrypt_redis_config(&mut config.redis)?;

        // 3. 加密JWT密钥
        if !self.is_encrypted_value(&config.jwt.secret) {
            let encrypted = self.encrypt_config_value(
                "jwt.secret",
                &config.jwt.secret,
                ConfigSecurityLevel::Secret,
            )?;
            config.jwt.secret = encrypted;
        }

        // 4. 加密加密密钥本身（使用轮转密钥）
        if !self.is_encrypted_value(&config.encryption.key) {
            let encrypted = self.encrypt_config_value(
                "encryption.key",
                &config.encryption.key,
                ConfigSecurityLevel::Secret,
            )?;
            config.encryption.key = encrypted;
        }

        // 5. 加密云服务配置
        self.encrypt_cloud_service_config(&mut config.cloud_service)?;

        // 6. 加密存储配置
        self.encrypt_storage_config(&mut config.storage)?;

        // 7. 加密邮件配置
        self.encrypt_email_config(&mut config.email)?;

        // 8. 加密短信配置
        self.encrypt_sms_config(&mut config.sms)?;

        // 9. 加密支付渠道配置
        self.encrypt_payment_config(&mut config.payment)?;

        // 10. 加密安全配置
        self.encrypt_security_config(&mut config.security)?;

        // 11. 加密队列配置
        self.encrypt_queue_config(&mut config.queue)?;

        // 12. 加密扩展配置中的敏感信息
        self.encrypt_extensions(&mut config.extensions)?;

        info!("Configuration encrypted successfully");
        Ok(())
    }

    /// 解密整个配置
    pub fn decrypt_config(&self, config: &mut crate::AppConfig) -> ConfigResult<()> {
        info!("Decrypting configuration");

        // 1. 解密数据库配置中的敏感信息
        self.decrypt_database_config(&mut config.database)?;

        // 2. 解密Redis密码
        self.decrypt_redis_config(&mut config.redis)?;

        // 3. 解密JWT密钥
        if self.is_encrypted_value(&config.jwt.secret) {
            let decrypted = self.decrypt_config_value("jwt.secret", &config.jwt.secret)?;
            config.jwt.secret = decrypted;
        }

        // 4. 解密切换密钥（使用轮转密钥）
        if self.is_encrypted_value(&config.encryption.key) {
            let decrypted = self.decrypt_config_value("encryption.key", &config.encryption.key)?;
            config.encryption.key = decrypted;
        }

        // 5. 解密云服务配置
        self.decrypt_cloud_service_config(&mut config.cloud_service)?;

        // 6. 解密存储配置
        self.decrypt_storage_config(&mut config.storage)?;

        // 7. 解密邮件配置
        self.decrypt_email_config(&mut config.email)?;

        // 8. 解密短信配置
        self.decrypt_sms_config(&mut config.sms)?;

        // 9. 解密支付渠道配置
        self.decrypt_payment_config(&mut config.payment)?;

        // 10. 解密安全配置
        self.decrypt_security_config(&mut config.security)?;

        // 11. 解密队列配置
        self.decrypt_queue_config(&mut config.queue)?;

        // 12. 解密扩展配置中的敏感信息
        self.decrypt_extensions(&mut config.extensions)?;

        info!("Configuration decrypted successfully");
        Ok(())
    }
    /// 加密数据库配置
    fn encrypt_database_config(&self, config: &mut crate::DatabaseConfig) -> ConfigResult<()> {
        // 加密数据库连接URL中的密码部分
        if !config.url.is_empty() {
            let encrypted_url = self.encrypt_database_url(&config.url)?;
            config.url = encrypted_url;
        }

        // 加密SSL证书路径中的敏感信息
        if let Some(cert_path) = &config.ssl_client_key_path {
            if self.is_encrypted_value(cert_path) {
                let decrypted =
                    self.decrypt_config_value("database.ssl_client_key_path", cert_path)?;
                let encrypted = self.encrypt_config_value(
                    "database.ssl_client_key_path",
                    &decrypted,
                    ConfigSecurityLevel::Sensitive,
                )?;
                config.ssl_client_key_path = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密数据库配置
    fn decrypt_database_config(&self, config: &mut crate::DatabaseConfig) -> ConfigResult<()> {
        // 解密数据库连接URL
        if self.is_encrypted_value(&config.url) {
            let decrypted = self.decrypt_database_url(&config.url)?;
            config.url = decrypted;
        }

        // 解密SSL证书路径
        if let Some(cert_path) = &config.ssl_client_key_path {
            if self.is_encrypted_value(cert_path) {
                let decrypted =
                    self.decrypt_config_value("database.ssl_client_key_path", cert_path)?;
                config.ssl_client_key_path = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密数据库URL（提取密码部分加密）
    pub fn encrypt_database_url(&self, url: &str) -> ConfigResult<String> {
        // 使用正则表达式提取密码部分，处理各种URL格式
        let url_pattern = regex::Regex::new(r"^(\w+://[^:]+:)([^@]*)(@.+)$").unwrap();

        if let Some(captures) = url_pattern.captures(url) {
            let prefix = captures.get(1).map(|m| m.as_str()).unwrap_or("");
            let password = captures.get(2).map(|m| m.as_str()).unwrap_or("");
            let suffix = captures.get(3).map(|m| m.as_str()).unwrap_or("");

            // 如果密码为空，直接返回原URL
            if password.is_empty() {
                return Ok(url.to_string());
            }

            // 先对密码进行URL解码（如果已编码）
            let decoded_password = percent_encoding::percent_decode_str(password)
                .decode_utf8_lossy()
                .to_string();

            // 加密解码后的密码
            let encrypted_password = self.encrypt_config_value(
                "database.password",
                &decoded_password,
                ConfigSecurityLevel::Sensitive,
            )?;

            // 加密后可能包含特殊字符，需要进行URL编码
            let encoded_password = percent_encoding::percent_encode(
                encrypted_password.as_bytes(),
                percent_encoding::NON_ALPHANUMERIC,
            )
            .to_string();

            // 重建URL
            return Ok(format!("{}{}{}", prefix, encoded_password, suffix));
        }

        // 如果URL解析失败或没有密码，直接返回原URL
        Ok(url.to_string())
    }

    /// 解密数据库URL
    pub fn decrypt_database_url(&self, url: &str) -> ConfigResult<String> {
        let url_pattern = regex::Regex::new(r"^(\w+://[^:]+:)([^@]*)(@.+)$").unwrap();

        if let Some(captures) = url_pattern.captures(url) {
            let prefix = captures.get(1).map(|m| m.as_str()).unwrap_or("");
            let password = captures.get(2).map(|m| m.as_str()).unwrap_or("");
            let suffix = captures.get(3).map(|m| m.as_str()).unwrap_or("");

            if !password.is_empty() {
                // URL解码密码部分
                let decoded_password = percent_encoding::percent_decode_str(password)
                    .decode_utf8_lossy()
                    .to_string();

                // 检查密码是否已加密
                if self.is_encrypted_value(&decoded_password) {
                    // 解密密码
                    let decrypted_password =
                        self.decrypt_config_value("database.password", &decoded_password)?;

                    // 解密后的密码可能包含特殊字符，需要URL编码
                    let encoded_password = percent_encoding::percent_encode(
                        decrypted_password.as_bytes(),
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string();

                    // 重建URL
                    return Ok(format!("{}{}{}", prefix, encoded_password, suffix));
                }
            }
        }

        // 如果URL解析失败或密码未加密，直接返回原URL
        Ok(url.to_string())
    }
    /// 加密Redis配置
    fn encrypt_redis_config(&self, config: &mut crate::RedisConfig) -> ConfigResult<()> {
        // 加密Redis密码
        if let Some(password) = &config.password {
            if !self.is_encrypted_value(password) {
                let encrypted = self.encrypt_config_value(
                    "redis.password",
                    password,
                    ConfigSecurityLevel::Sensitive,
                )?;
                config.password = Some(encrypted);
            }
        }

        // 加密Redis URL中的密码部分
        if !config.url.is_empty() {
            let encrypted_url = self.encrypt_redis_url(&config.url)?;
            config.url = encrypted_url;
        }

        Ok(())
    }

    /// 解密Redis配置
    fn decrypt_redis_config(&self, config: &mut crate::RedisConfig) -> ConfigResult<()> {
        // 解密Redis密码
        if let Some(password) = &config.password {
            if self.is_encrypted_value(password) {
                let decrypted = self.decrypt_config_value("redis.password", password)?;
                config.password = Some(decrypted);
            }
        }

        // 解密Redis URL
        if self.is_encrypted_value(&config.url) {
            let decrypted = self.decrypt_redis_url(&config.url)?;
            config.url = decrypted;
        }

        Ok(())
    }

    /// 加密Redis URL
    fn encrypt_redis_url(&self, url: &str) -> ConfigResult<String> {
        // 简单的URL模式匹配来加密密码
        let redis_url_pattern = regex::Regex::new(r"redis://([^:]+):([^@]+)@(.+)").unwrap();

        if let Some(captures) = redis_url_pattern.captures(url) {
            let username = captures.get(1).map(|m| m.as_str()).unwrap_or("");
            let password = captures.get(2).map(|m| m.as_str()).unwrap_or("");
            let rest = captures.get(3).map(|m| m.as_str()).unwrap_or("");

            if !password.is_empty() {
                // 加密密码
                let encrypted_password = self.encrypt_config_value(
                    "redis.url_password",
                    password,
                    ConfigSecurityLevel::Sensitive,
                )?;

                // 重建URL
                return Ok(format!(
                    "redis://{}:{}@{}",
                    username, encrypted_password, rest
                ));
            }
        }

        Ok(url.to_string())
    }

    /// 解密Redis URL
    fn decrypt_redis_url(&self, url: &str) -> ConfigResult<String> {
        let redis_url_pattern = regex::Regex::new(r"redis://([^:]+):([^@]+)@(.+)").unwrap();

        if let Some(captures) = redis_url_pattern.captures(url) {
            let username = captures.get(1).map(|m| m.as_str()).unwrap_or("");
            let password = captures.get(2).map(|m| m.as_str()).unwrap_or("");
            let rest = captures.get(3).map(|m| m.as_str()).unwrap_or("");

            if !password.is_empty() && self.is_encrypted_value(password) {
                // 解密密码
                let decrypted_password =
                    self.decrypt_config_value("redis.url_password", password)?;

                // 重建URL
                return Ok(format!(
                    "redis://{}:{}@{}",
                    username, decrypted_password, rest
                ));
            }
        }

        Ok(url.to_string())
    }

    /// 加密云服务配置
    fn encrypt_cloud_service_config(
        &self,
        config: &mut crate::CloudServiceConfig,
    ) -> ConfigResult<()> {
        // 加密腾讯云配置
        self.encrypt_tencent_config(&mut config.tencent)?;

        // 加密阿里云配置
        self.encrypt_aliyun_config(&mut config.aliyun)?;

        // 加密AWS配置
        self.encrypt_aws_config(&mut config.aws)?;

        // 加密华为云配置
        self.encrypt_huawei_config(&mut config.huawei)?;

        Ok(())
    }

    /// 解密云服务配置
    fn decrypt_cloud_service_config(
        &self,
        config: &mut crate::CloudServiceConfig,
    ) -> ConfigResult<()> {
        // 解密腾讯云配置
        self.decrypt_tencent_config(&mut config.tencent)?;

        // 解密阿里云配置
        self.decrypt_aliyun_config(&mut config.aliyun)?;

        // 解密AWS配置
        self.decrypt_aws_config(&mut config.aws)?;

        // 解密华为云配置
        self.decrypt_huawei_config(&mut config.huawei)?;

        Ok(())
    }

    /// 加密腾讯云配置
    fn encrypt_tencent_config(&self, config: &mut crate::TencentCloudConfig) -> ConfigResult<()> {
        if let Some(secret_id) = &config.secret_id {
            if !self.is_encrypted_value(secret_id) {
                let encrypted = self.encrypt_config_value(
                    "tencent.secret_id",
                    secret_id,
                    ConfigSecurityLevel::Sensitive,
                )?;
                config.secret_id = Some(encrypted);
            }
        }

        if let Some(secret_key) = &config.secret_key {
            if !self.is_encrypted_value(secret_key) {
                let encrypted = self.encrypt_config_value(
                    "tencent.secret_key",
                    secret_key,
                    ConfigSecurityLevel::Secret,
                )?;
                config.secret_key = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密腾讯云配置
    fn decrypt_tencent_config(&self, config: &mut crate::TencentCloudConfig) -> ConfigResult<()> {
        if let Some(secret_id) = &config.secret_id {
            if self.is_encrypted_value(secret_id) {
                let decrypted = self.decrypt_config_value("tencent.secret_id", secret_id)?;
                config.secret_id = Some(decrypted);
            }
        }

        if let Some(secret_key) = &config.secret_key {
            if self.is_encrypted_value(secret_key) {
                let decrypted = self.decrypt_config_value("tencent.secret_key", secret_key)?;
                config.secret_key = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密阿里云配置
    fn encrypt_aliyun_config(&self, config: &mut crate::AliyunCloudConfig) -> ConfigResult<()> {
        if let Some(access_key_id) = &config.access_key_id {
            if !self.is_encrypted_value(access_key_id) {
                let encrypted = self.encrypt_config_value(
                    "aliyun.access_key_id",
                    access_key_id,
                    ConfigSecurityLevel::Sensitive,
                )?;
                config.access_key_id = Some(encrypted);
            }
        }

        if let Some(access_key_secret) = &config.access_key_secret {
            if !self.is_encrypted_value(access_key_secret) {
                let encrypted = self.encrypt_config_value(
                    "aliyun.access_key_secret",
                    access_key_secret,
                    ConfigSecurityLevel::Secret,
                )?;
                config.access_key_secret = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密阿里云配置
    fn decrypt_aliyun_config(&self, config: &mut crate::AliyunCloudConfig) -> ConfigResult<()> {
        if let Some(access_key_id) = &config.access_key_id {
            if self.is_encrypted_value(access_key_id) {
                let decrypted = self.decrypt_config_value("aliyun.access_key_id", access_key_id)?;
                config.access_key_id = Some(decrypted);
            }
        }

        if let Some(access_key_secret) = &config.access_key_secret {
            if self.is_encrypted_value(access_key_secret) {
                let decrypted =
                    self.decrypt_config_value("aliyun.access_key_secret", access_key_secret)?;
                config.access_key_secret = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密AWS配置
    fn encrypt_aws_config(&self, config: &mut crate::AwsCloudConfig) -> ConfigResult<()> {
        if let Some(access_key_id) = &config.access_key_id {
            if !self.is_encrypted_value(access_key_id) {
                let encrypted = self.encrypt_config_value(
                    "aws.access_key_id",
                    access_key_id,
                    ConfigSecurityLevel::Sensitive,
                )?;
                config.access_key_id = Some(encrypted);
            }
        }

        if let Some(secret_access_key) = &config.secret_access_key {
            if !self.is_encrypted_value(secret_access_key) {
                let encrypted = self.encrypt_config_value(
                    "aws.secret_access_key",
                    secret_access_key,
                    ConfigSecurityLevel::Secret,
                )?;
                config.secret_access_key = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密AWS配置
    fn decrypt_aws_config(&self, config: &mut crate::AwsCloudConfig) -> ConfigResult<()> {
        if let Some(access_key_id) = &config.access_key_id {
            if self.is_encrypted_value(access_key_id) {
                let decrypted = self.decrypt_config_value("aws.access_key_id", access_key_id)?;
                config.access_key_id = Some(decrypted);
            }
        }

        if let Some(secret_access_key) = &config.secret_access_key {
            if self.is_encrypted_value(secret_access_key) {
                let decrypted =
                    self.decrypt_config_value("aws.secret_access_key", secret_access_key)?;
                config.secret_access_key = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密华为云配置
    fn encrypt_huawei_config(&self, config: &mut crate::HuaweiCloudConfig) -> ConfigResult<()> {
        if let Some(access_key_id) = &config.access_key_id {
            if !self.is_encrypted_value(access_key_id) {
                let encrypted = self.encrypt_config_value(
                    "huawei.access_key_id",
                    access_key_id,
                    ConfigSecurityLevel::Sensitive,
                )?;
                config.access_key_id = Some(encrypted);
            }
        }

        if let Some(secret_access_key) = &config.secret_access_key {
            if !self.is_encrypted_value(secret_access_key) {
                let encrypted = self.encrypt_config_value(
                    "huawei.secret_access_key",
                    secret_access_key,
                    ConfigSecurityLevel::Secret,
                )?;
                config.secret_access_key = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密华为云配置
    fn decrypt_huawei_config(&self, config: &mut crate::HuaweiCloudConfig) -> ConfigResult<()> {
        if let Some(access_key_id) = &config.access_key_id {
            if self.is_encrypted_value(access_key_id) {
                let decrypted = self.decrypt_config_value("huawei.access_key_id", access_key_id)?;
                config.access_key_id = Some(decrypted);
            }
        }

        if let Some(secret_access_key) = &config.secret_access_key {
            if self.is_encrypted_value(secret_access_key) {
                let decrypted =
                    self.decrypt_config_value("huawei.secret_access_key", secret_access_key)?;
                config.secret_access_key = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密存储配置
    fn encrypt_storage_config(&self, config: &mut crate::StorageConfig) -> ConfigResult<()> {
        // 加密S3存储配置
        if let Some(access_key_id) = &config.s3.access_key_id {
            if !self.is_encrypted_value(access_key_id) {
                let encrypted = self.encrypt_config_value(
                    "storage.s3.access_key_id",
                    access_key_id,
                    ConfigSecurityLevel::Sensitive,
                )?;
                config.s3.access_key_id = Some(encrypted);
            }
        }

        if let Some(secret_access_key) = &config.s3.secret_access_key {
            if !self.is_encrypted_value(secret_access_key) {
                let encrypted = self.encrypt_config_value(
                    "storage.s3.secret_access_key",
                    secret_access_key,
                    ConfigSecurityLevel::Secret,
                )?;
                config.s3.secret_access_key = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密存储配置
    fn decrypt_storage_config(&self, config: &mut crate::StorageConfig) -> ConfigResult<()> {
        // 解密S3存储配置
        if let Some(access_key_id) = &config.s3.access_key_id {
            if self.is_encrypted_value(access_key_id) {
                let decrypted =
                    self.decrypt_config_value("storage.s3.access_key_id", access_key_id)?;
                config.s3.access_key_id = Some(decrypted);
            }
        }

        if let Some(secret_access_key) = &config.s3.secret_access_key {
            if self.is_encrypted_value(secret_access_key) {
                let decrypted =
                    self.decrypt_config_value("storage.s3.secret_access_key", secret_access_key)?;
                config.s3.secret_access_key = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密邮件配置
    fn encrypt_email_config(&self, config: &mut crate::EmailConfig) -> ConfigResult<()> {
        if let Some(password) = &config.password {
            if !self.is_encrypted_value(password) {
                let encrypted = self.encrypt_config_value(
                    "email.password",
                    password,
                    ConfigSecurityLevel::Sensitive,
                )?;
                config.password = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密邮件配置
    fn decrypt_email_config(&self, config: &mut crate::EmailConfig) -> ConfigResult<()> {
        if let Some(password) = &config.password {
            if self.is_encrypted_value(password) {
                let decrypted = self.decrypt_config_value("email.password", password)?;
                config.password = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密短信配置
    fn encrypt_sms_config(&self, config: &mut crate::SmsConfig) -> ConfigResult<()> {
        if let Some(access_key_secret) = &config.access_key_secret {
            if !self.is_encrypted_value(access_key_secret) {
                let encrypted = self.encrypt_config_value(
                    "sms.access_key_secret",
                    access_key_secret,
                    ConfigSecurityLevel::Secret,
                )?;
                config.access_key_secret = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密短信配置
    fn decrypt_sms_config(&self, config: &mut crate::SmsConfig) -> ConfigResult<()> {
        if let Some(access_key_secret) = &config.access_key_secret {
            if self.is_encrypted_value(access_key_secret) {
                let decrypted =
                    self.decrypt_config_value("sms.access_key_secret", access_key_secret)?;
                config.access_key_secret = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密支付配置
    fn encrypt_payment_config(&self, config: &mut crate::PaymentConfig) -> ConfigResult<()> {
        // 加密各个支付渠道的私钥
        for (channel_name, channel_config) in &mut config.channels {
            if !self.is_encrypted_value(&channel_config.private_key) {
                let encrypted = self.encrypt_config_value(
                    &format!("payment.channels.{}.private_key", channel_name),
                    &channel_config.private_key,
                    ConfigSecurityLevel::Secret,
                )?;
                channel_config.private_key = encrypted;
            }

            if let Some(public_key) = &channel_config.public_key {
                if !self.is_encrypted_value(public_key) {
                    let encrypted = self.encrypt_config_value(
                        &format!("payment.channels.{}.public_key", channel_name),
                        public_key,
                        ConfigSecurityLevel::Sensitive,
                    )?;
                    channel_config.public_key = Some(encrypted);
                }
            }
        }

        Ok(())
    }

    /// 解密支付配置
    fn decrypt_payment_config(&self, config: &mut crate::PaymentConfig) -> ConfigResult<()> {
        // 解密各个支付渠道的私钥
        for (channel_name, channel_config) in &mut config.channels {
            if self.is_encrypted_value(&channel_config.private_key) {
                let decrypted = self.decrypt_config_value(
                    &format!("payment.channels.{}.private_key", channel_name),
                    &channel_config.private_key,
                )?;
                channel_config.private_key = decrypted;
            }

            if let Some(public_key) = &channel_config.public_key {
                if self.is_encrypted_value(public_key) {
                    let decrypted = self.decrypt_config_value(
                        &format!("payment.channels.{}.public_key", channel_name),
                        public_key,
                    )?;
                    channel_config.public_key = Some(decrypted);
                }
            }
        }

        Ok(())
    }

    /// 加密安全配置
    fn encrypt_security_config(&self, config: &mut crate::SecurityConfig) -> ConfigResult<()> {
        if let Some(signing_key) = &config.signing_key {
            if !self.is_encrypted_value(signing_key) {
                let encrypted = self.encrypt_config_value(
                    "security.signing_key",
                    signing_key,
                    ConfigSecurityLevel::Secret,
                )?;
                config.signing_key = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密安全配置
    fn decrypt_security_config(&self, config: &mut crate::SecurityConfig) -> ConfigResult<()> {
        if let Some(signing_key) = &config.signing_key {
            if self.is_encrypted_value(signing_key) {
                let decrypted = self.decrypt_config_value("security.signing_key", signing_key)?;
                config.signing_key = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密队列配置
    fn encrypt_queue_config(&self, config: &mut crate::QueueConfig) -> ConfigResult<()> {
        // 加密SQS配置
        if let Some(secret_access_key) = &config.sqs.secret_access_key {
            if !self.is_encrypted_value(secret_access_key) {
                let encrypted = self.encrypt_config_value(
                    "queue.sqs.secret_access_key",
                    secret_access_key,
                    ConfigSecurityLevel::Secret,
                )?;
                config.sqs.secret_access_key = Some(encrypted);
            }
        }

        Ok(())
    }

    /// 解密队列配置
    fn decrypt_queue_config(&self, config: &mut crate::QueueConfig) -> ConfigResult<()> {
        // 解密SQS配置
        if let Some(secret_access_key) = &config.sqs.secret_access_key {
            if self.is_encrypted_value(secret_access_key) {
                let decrypted =
                    self.decrypt_config_value("queue.sqs.secret_access_key", secret_access_key)?;
                config.sqs.secret_access_key = Some(decrypted);
            }
        }

        Ok(())
    }

    /// 加密扩展配置
    fn encrypt_extensions(
        &self,
        extensions: &mut std::collections::HashMap<String, serde_json::Value>,
    ) -> ConfigResult<()> {
        let mut to_encrypt = Vec::new();

        // 找出需要加密的扩展配置
        for (key, value) in extensions.iter() {
            if let serde_json::Value::String(str_value) = value {
                // 检查是否为敏感扩展配置（根据命名约定）
                if key.contains("password")
                    || key.contains("secret")
                    || key.contains("key")
                    || key.contains("token")
                {
                    if !self.is_encrypted_value(str_value) {
                        to_encrypt.push((key.clone(), str_value.clone()));
                    }
                }
            }
        }

        // 加密扩展配置
        for (key, value) in to_encrypt {
            let encrypted = self.encrypt_config_value(
                &format!("extensions.{}", key),
                &value,
                ConfigSecurityLevel::Sensitive,
            )?;
            extensions.insert(key, serde_json::Value::String(encrypted));
        }

        Ok(())
    }

    /// 解密扩展配置
    fn decrypt_extensions(
        &self,
        extensions: &mut std::collections::HashMap<String, serde_json::Value>,
    ) -> ConfigResult<()> {
        let mut to_decrypt = Vec::new();

        // 找出需要解密的扩展配置
        for (key, value) in extensions.iter() {
            if let serde_json::Value::String(str_value) = value {
                if self.is_encrypted_value(str_value) {
                    to_decrypt.push((key.clone(), str_value.clone()));
                }
            }
        }

        // 解密扩展配置
        for (key, value) in to_decrypt {
            let decrypted = self.decrypt_config_value(&format!("extensions.{}", key), &value)?;
            extensions.insert(key, serde_json::Value::String(decrypted));
        }

        Ok(())
    }

    /// 检查值是否已加密
    pub fn is_encrypted_value(&self, value: &str) -> bool {
        // 检查未编码的情况
        if value.starts_with(ENCRYPTION_PREFIX) && value.ends_with(ENCRYPTION_SUFFIX) {
            return true;
        }

        // 检查URL编码的情况（%5B -> [，%5D -> ]）
        let encoded_prefix = ENCRYPTION_PREFIX
            .replace("[", "%5B")
            .replace("]", "%5D")
            .replace(":", "%3A");

        if value.contains(&encoded_prefix) {
            return true;
        }

        // 或者直接检查是否包含 ENC%5B（URL编码的 ENC[）
        value.contains("ENC%5B")
    }

    /// 解析加密值
    fn parse_encrypted_value(&self, value: &str) -> ConfigResult<(ConfigSecurityLevel, String)> {
        if !self.is_encrypted_value(value) {
            return Err(ConfigError::DecryptionError(
                "Value is not encrypted".to_string(),
            ));
        }

        let inner = &value[4..value.len() - 1]; // 移除"ENC["和"]"
        let parts: Vec<&str> = inner.splitn(2, ':').collect();

        if parts.len() != 2 {
            return Err(ConfigError::DecryptionError(
                "Invalid encrypted value format".to_string(),
            ));
        }

        let security_level_str = parts[0];
        let encrypted_value = parts[1];

        let security_level = match security_level_str {
            "public" => ConfigSecurityLevel::Public,
            "internal" => ConfigSecurityLevel::Internal,
            "sensitive" => ConfigSecurityLevel::Sensitive,
            "secret" => ConfigSecurityLevel::Secret,
            _ => {
                return Err(ConfigError::DecryptionError(format!(
                    "Unknown security level: {}",
                    security_level_str
                )));
            }
        };

        Ok((security_level, encrypted_value.to_string()))
    }

    /// 检查是否需要加密
    fn should_encrypt(&self, security_level: ConfigSecurityLevel) -> bool {
        let levels = self.security_levels.read();
        levels.contains(&security_level)
    }

    /// 检查是否需要解密
    fn should_decrypt(&self, security_level: ConfigSecurityLevel) -> bool {
        self.should_encrypt(security_level)
    }

    /// 设置需要加密的安全级别
    pub fn set_security_levels(&self, levels: Vec<ConfigSecurityLevel>) {
        *self.security_levels.write() = levels;
    }

    /// 获取当前加密管理器
    pub fn encryption_manager(&self) -> Arc<EncryptionManager> {
        self.encryption_manager.clone()
    }
}

/// 便捷函数：加密配置值
pub fn encrypt_config_value(
    key: &str,
    value: &str,
    security_level: ConfigSecurityLevel,
) -> ConfigResult<String> {
    // 从环境变量获取加密密钥
    let base64_key = std::env::var(ENCRYPTION_KEY_ENV)
        .map_err(|e| ConfigError::EnvError(format!("LUSER_ENCRYPTION_KEY not set: {}", e)))?;

    let encryption_manager =
        EncryptionManager::from_base64_key(EncryptionAlgorithm::Aes256Gcm, &base64_key)?;
    let encryptor = ConfigEncryptor::new(encryption_manager);

    encryptor.encrypt_config_value(key, value, security_level)
}

/// 便捷函数：解密配置值
pub fn decrypt_config_value(key: &str, value: &str) -> ConfigResult<String> {
    // 从环境变量获取加密密钥
    let base64_key = std::env::var(ENCRYPTION_KEY_ENV)
        .map_err(|e| ConfigError::EnvError(format!("LUSER_ENCRYPTION_KEY not set: {}", e)))?;

    let encryption_manager =
        EncryptionManager::from_base64_key(EncryptionAlgorithm::Aes256Gcm, &base64_key)?;
    let encryptor = ConfigEncryptor::new(encryption_manager);

    encryptor.decrypt_config_value(key, value)
}

// 全局加密器实例
lazy_static::lazy_static! {
    static ref GLOBAL_ENCRYPTOR: parking_lot::RwLock<Option<ConfigEncryptor>> = parking_lot::RwLock::new(None);
}

/// 初始化全局加密器
pub fn init_global_encryptor() -> ConfigResult<()> {
    let mut global_encryptor = GLOBAL_ENCRYPTOR.write();
    if global_encryptor.is_none() {
        // 从环境变量获取加密密钥
        let base64_key = std::env::var(ENCRYPTION_KEY_ENV).unwrap_or_else(|_| {
            warn!("LUSER_ENCRYPTION_KEY not set, using default key");
            EncryptionManager::generate_base64_key(EncryptionAlgorithm::Aes256Gcm)
                .unwrap_or_else(|_| base64::encode(vec![0u8; 32]))
        });

        let encryption_manager =
            EncryptionManager::from_base64_key(EncryptionAlgorithm::Aes256Gcm, &base64_key)?;
        *global_encryptor = Some(ConfigEncryptor::new(encryption_manager));
    }
    Ok(())
}

/// 获取全局加密器
pub fn get_global_encryptor() -> ConfigResult<ConfigEncryptor> {
    let global_encryptor = GLOBAL_ENCRYPTOR.read();
    global_encryptor
        .as_ref()
        .cloned()
        .ok_or_else(|| ConfigError::NotInitialized("Global encryptor not initialized".to_string()))
}

/// 密钥管理器
#[derive(Debug, Clone)]
pub struct KeyManager {
    current_key: Arc<RwLock<Vec<u8>>>,
    key_history: Arc<RwLock<Vec<KeyHistoryEntry>>>,
    rotation_interval: std::time::Duration,
}

/// 密钥历史记录
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyHistoryEntry {
    pub key_id: String,
    pub key: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
}

impl KeyManager {
    /// 创建新的密钥管理器
    pub fn new(initial_key: Vec<u8>, rotation_interval: std::time::Duration) -> ConfigResult<Self> {
        let key_id = Self::generate_key_id();

        let manager = Self {
            current_key: Arc::new(RwLock::new(initial_key.clone())),
            key_history: Arc::new(RwLock::new(vec![KeyHistoryEntry {
                key_id: key_id.clone(),
                key: initial_key,
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now()
                    + chrono::Duration::from_std(rotation_interval).unwrap(),
                active: true,
            }])),
            rotation_interval,
        };

        Ok(manager)
    }

    /// 生成密钥ID
    fn generate_key_id() -> String {
        let timestamp = chrono::Utc::now().timestamp();
        let random = rand::random::<u32>();
        format!("key_{}_{}", timestamp, random)
    }

    /// 轮换密钥
    pub fn rotate_key(&self) -> ConfigResult<String> {
        let new_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        let key_id = Self::generate_key_id();

        // 更新当前密钥
        *self.current_key.write() = new_key.clone();

        // 将旧密钥标记为不活跃
        let mut history = self.key_history.write();
        for entry in history.iter_mut() {
            entry.active = false;
        }

        // 添加新密钥到历史记录
        history.push(KeyHistoryEntry {
            key_id: key_id.clone(),
            key: new_key,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now()
                + chrono::Duration::from_std(self.rotation_interval).unwrap(),
            active: true,
        });

        // 清理过期的密钥（保留最近3个）
        if history.len() > 3 {
            history.remove(0);
        }

        Ok(key_id)
    }

    /// 获取当前密钥
    pub fn get_current_key(&self) -> Vec<u8> {
        self.current_key.read().clone()
    }

    /// 根据密钥ID获取密钥
    pub fn get_key_by_id(&self, key_id: &str) -> Option<Vec<u8>> {
        let history = self.key_history.read();
        history
            .iter()
            .find(|entry| entry.key_id == key_id)
            .map(|entry| entry.key.clone())
    }

    /// 检查是否需要轮换密钥
    pub fn should_rotate_key(&self) -> bool {
        let history = self.key_history.read();
        if let Some(active_key) = history.iter().find(|entry| entry.active) {
            chrono::Utc::now() >= active_key.expires_at
        } else {
            true
        }
    }

    /// 解密使用旧密钥加密的数据
    pub fn decrypt_with_historical_keys(
        &self,
        encrypted_data: &[u8],
        encryption_manager: &EncryptionManager,
    ) -> ConfigResult<Vec<u8>> {
        // 首先尝试使用当前密钥解密
        match encryption_manager.decrypt(encrypted_data) {
            Ok(decrypted) => Ok(decrypted),
            Err(_) => {
                // 如果当前密钥失败，尝试使用历史密钥
                let history = self.key_history.read();

                for entry in history.iter() {
                    if !entry.active {
                        let temp_manager = EncryptionManager::new(
                            EncryptionAlgorithm::Aes256Gcm,
                            entry.key.clone(),
                        )?;

                        if let Ok(decrypted) = temp_manager.decrypt(encrypted_data) {
                            return Ok(decrypted);
                        }
                    }
                }

                Err(ConfigError::DecryptionError(
                    "Failed to decrypt with any historical key".to_string(),
                ))
            }
        }
    }

    /// 导出密钥历史（加密存储）
    pub fn export_key_history(&self, export_key: &[u8]) -> ConfigResult<Vec<u8>> {
        let history = self.key_history.read();

        let export_data = serde_json::to_vec(&*history).map_err(|e| {
            ConfigError::SerializationFailed(format!("Failed to serialize key history: {}", e))
        })?;

        // 使用导出密钥加密历史数据
        let export_manager =
            EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, export_key.to_vec())?;

        export_manager.encrypt(&export_data)
    }

    /// 导入密钥历史
    pub fn import_key_history(
        &mut self,
        encrypted_history: &[u8],
        import_key: &[u8],
    ) -> ConfigResult<()> {
        // 解密历史数据
        let import_manager =
            EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, import_key.to_vec())?;

        let decrypted = import_manager.decrypt(encrypted_history)?;

        // 反序列化历史数据
        let history: Vec<KeyHistoryEntry> = serde_json::from_slice(&decrypted).map_err(|e| {
            ConfigError::DeserializationFailed(format!("Failed to deserialize key history: {}", e))
        })?;

        // 更新密钥管理器
        if let Some(active_key) = history.iter().find(|entry| entry.active) {
            *self.current_key.write() = active_key.key.clone();
        }

        *self.key_history.write() = history;

        Ok(())
    }
}
