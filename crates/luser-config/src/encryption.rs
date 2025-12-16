use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use parking_lot::RwLock;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tracing::{error, info, instrument, warn};

use crate::{
    ConfigError, ConfigResult, ConfigSecurityLevel, ENCRYPTION_KEY_ENV, ENCRYPTION_PREFIX,
    ENCRYPTION_SUFFIX, KEY_BACKUP_COUNT,
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
    key_manager: Option<Arc<RwLock<KeyManager>>>,
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
        rng.fill(&mut nonce).expect("生成 nonce 失败");
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
                "密钥长度无效：预期为 {}，结果为 {}",
                algorithm.key_length(),
                key.len()
            )));
        }

        Ok(Self {
            algorithm,
            key: Arc::new(RwLock::new(key)),
            nonce_generator: Arc::new(SecureNonceGenerator),
            key_manager: None, // 初始化为 None
        })
    }
    /// 创建新的加密管理器（带密钥管理）
    pub fn new_with_key_manager(
        algorithm: EncryptionAlgorithm,
        key: Vec<u8>,
        rotation_interval: std::time::Duration,
    ) -> ConfigResult<Self> {
        // 验证密钥长度
        if key.len() != algorithm.key_length() {
            return Err(ConfigError::EncryptionError(format!(
                "密钥长度无效：预期为 {}，结果为 {}",
                algorithm.key_length(),
                key.len()
            )));
        }

        // 创建 KeyManager
        let key_manager = KeyManager::new(key.clone(), rotation_interval)?;

        Ok(Self {
            algorithm,
            key: Arc::new(RwLock::new(key)),
            nonce_generator: Arc::new(SecureNonceGenerator),
            key_manager: Some(Arc::new(RwLock::new(key_manager))),
        })
    }
    /// 从base64编码的密钥创建加密管理器
    pub fn from_base64_key(algorithm: EncryptionAlgorithm, base64_key: &str) -> ConfigResult<Self> {
        let key = STANDARD.decode(base64_key).map_err(|e| {
            ConfigError::EncryptionError(format!("解码 base64 密钥失败: {}", e))
        })?;

        Self::new(algorithm, key)
    }

    /// 从环境变量创建加密管理器
    pub fn from_env(algorithm: EncryptionAlgorithm, env_var: &str) -> ConfigResult<Self> {
        let base64_key = std::env::var(env_var).map_err(|e| {
            ConfigError::EnvError(format!("读取环境变量失败 {}: {}", env_var, e))
        })?;

        Self::from_base64_key(algorithm, &base64_key)
    }

    /// 生成随机密钥
    pub fn generate_key(algorithm: EncryptionAlgorithm) -> ConfigResult<Vec<u8>> {
        let length = algorithm.key_length();
        let mut key = vec![0u8; length];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut key)
            .map_err(|e| ConfigError::EncryptionError(format!("生成密钥失败： {}", e)))?;

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
        // 如果有 KeyManager，使用其当前密钥
        let key = if let Some(key_manager) = &self.key_manager {
            key_manager.read().get_current_key()
        } else {
            self.key.read().clone()
        };

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
        // 如果有 KeyManager，使用其当前密钥
        let key = if let Some(key_manager) = &self.key_manager {
            key_manager.read().get_current_key()
        } else {
            self.key.read().clone()
        };
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
            ConfigError::EncryptionError(format!("无法解码 base64 密文 ciphertext: {}", e))
        })?;

        let plaintext = self.decrypt(&ciphertext_bytes)?;
        String::from_utf8(plaintext).map_err(|e| {
            ConfigError::EncryptionError(format!(
                "未能将解密数据转换为字符串: {}",
                e
            ))
        })
    }

    /// 轮换密钥
    pub fn rotate_key(&self) -> ConfigResult<String> {
        if let Some(key_manager) = &self.key_manager {
            let mut key_manager = key_manager.write();
            let new_key_id = key_manager.rotate_key()?;

            // 重要：更新 EncryptionManager 的当前密钥
            let new_key = key_manager.get_current_key();
            *self.key.write() = new_key;

            info!("加密密钥已成功轮换: {}", new_key_id);
            Ok(new_key_id)
        } else {
            Err(ConfigError::EncryptionError(
                "密钥管理未启用".to_string(),
            ))
        }
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
            .map_err(|e| ConfigError::EncryptionError(format!("创建cipher失败: {}", e)))?;

        let nonce_bytes = self
            .nonce_generator
            .generate_nonce(self.algorithm.nonce_length());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ConfigError::EncryptionError(format!("加密失败: {}", e)))?;

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
                "密文太短：预计至少为 {}，得到的是 {}",
                nonce_length,
                ciphertext.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| ConfigError::EncryptionError(format!("创建cipher失败 : {}", e)))?;

        let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(nonce_length);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|e| ConfigError::DecryptionError(format!("解密失败: {}", e)))?;

        Ok(plaintext)
    }

    /// ChaCha20-Poly1305加密
    fn encrypt_chacha20_poly1305(&self, key: &[u8], plaintext: &[u8]) -> ConfigResult<Vec<u8>> {
        // TODO 注意：这里使用AES-GCM作为替代，实际项目中应该实现ChaCha20-Poly1305
        // 由于依赖库限制，这里使用AES-GCM
        warn!("ChaCha20-Poly1305 未实现，改为使用 AES-GCM");
        self.encrypt_aes_gcm(key, plaintext)
    }

    /// ChaCha20-Poly1305解密
    fn decrypt_chacha20_poly1305(&self, key: &[u8], ciphertext: &[u8]) -> ConfigResult<Vec<u8>> {
        // TODO 注意：这里使用AES-GCM作为替代，实际项目中应该实现ChaCha20-Poly1305
        warn!("ChaCha20-Poly1305 未实现，改为使用 AES-GCM");
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
    /// 获取 key_manager 方法
    pub fn key_manager(&self) -> Option<Arc<RwLock<KeyManager>>> {
        self.key_manager.clone()
    }
    /// 启用密钥管理
    pub fn enable_key_management(
        &mut self,
        rotation_interval: std::time::Duration,
    ) -> ConfigResult<()> {
        if self.key_manager.is_some() {
            return Ok(());
        }

        let key = self.key.read().clone();
        let key_manager = KeyManager::new(key, rotation_interval)?;
        self.key_manager = Some(Arc::new(key_manager.into()));

        Ok(())
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
    /// 创建带密钥管理的加密器
    pub fn new_with_key_manager(
        algorithm: EncryptionAlgorithm,
        key: Vec<u8>,
        rotation_interval: std::time::Duration,
    ) -> ConfigResult<Self> {
        let encryption_manager =
            EncryptionManager::new_with_key_manager(algorithm, key, rotation_interval)?;
        Ok(Self {
            encryption_manager: Arc::new(encryption_manager),
            security_levels: Arc::new(RwLock::new(vec![
                ConfigSecurityLevel::Sensitive,
                ConfigSecurityLevel::Secret,
            ])),
        })
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

        info!("加密密钥的配置值: {}", key);

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

        info!("解密密钥的配置值： {}", key);

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
        info!("加密配置");

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

        info!("配置加密成功");
        Ok(())
    }

    /// 解密整个配置
    pub fn decrypt_config(&self, config: &mut crate::AppConfig) -> ConfigResult<()> {
        info!("解密配置");

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

        info!("配置解密成功");
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
                "值未加密".to_string(),
            ));
        }

        let inner = &value[4..value.len() - 1]; // 移除"ENC["和"]"
        let parts: Vec<&str> = inner.splitn(2, ':').collect();

        if parts.len() != 2 {
            return Err(ConfigError::DecryptionError(
                "加密值格式无效".to_string(),
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
                    "未知的安全级别: {}",
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
    /// 获取密钥管理器
    pub fn key_manager(&self) -> Option<Arc<RwLock<KeyManager>>> {
        self.encryption_manager.key_manager()
    }
    /// 启用密钥管理
    pub fn enable_key_management(
        &mut self,
        rotation_interval: std::time::Duration,
    ) -> ConfigResult<()> {
        // 由于 EncryptionManager 是不可变的，我们需要创建新的实例
        let mut encryption_manager = (*self.encryption_manager).clone();
        encryption_manager.enable_key_management(rotation_interval)?;
        self.encryption_manager = Arc::new(encryption_manager);
        Ok(())
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
        .map_err(|e| ConfigError::EnvError(format!("LUSER_ENCRYPTION_KEY 未设置: {}", e)))?;

    let encryption_manager =
        EncryptionManager::from_base64_key(EncryptionAlgorithm::Aes256Gcm, &base64_key)?;
    let encryptor = ConfigEncryptor::new(encryption_manager);

    encryptor.encrypt_config_value(key, value, security_level)
}

/// 便捷函数：解密配置值
pub fn decrypt_config_value(key: &str, value: &str) -> ConfigResult<String> {
    // 从环境变量获取加密密钥
    let base64_key = std::env::var(ENCRYPTION_KEY_ENV)
        .map_err(|e| ConfigError::EnvError(format!("LUSER_ENCRYPTION_KEY 未设置: {}", e)))?;

    let encryption_manager =
        EncryptionManager::from_base64_key(EncryptionAlgorithm::Aes256Gcm, &base64_key)?;
    let encryptor = ConfigEncryptor::new(encryption_manager);

    encryptor.decrypt_config_value(key, value)
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
        // 生成新密钥
        let new_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        let key_id = Self::generate_key_id();

        // 更新当前密钥
        *self.current_key.write() = new_key.clone();

        // 将旧密钥添加到历史记录并标记为不活跃
        let mut history = self.key_history.write();

        // 首先将所有密钥标记为不活跃
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
        if history.len() > KEY_BACKUP_COUNT {
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
                    "无法使用任何历史密钥解密".to_string(),
                ))
            }
        }
    }

    /// 导出密钥历史（加密存储）
    pub fn export_key_history(&self, export_key: &[u8]) -> ConfigResult<Vec<u8>> {
        let history = self.key_history.read();

        let export_data = serde_json::to_vec(&*history).map_err(|e| {
            ConfigError::SerializationFailed(format!("无法序列化密钥历史： {}", e))
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
            ConfigError::DeserializationFailed(format!("无法反序列化密钥历史: {}", e))
        })?;

        // 更新密钥管理器
        if let Some(active_key) = history.iter().find(|entry| entry.active) {
            *self.current_key.write() = active_key.key.clone();
        }

        *self.key_history.write() = history;

        Ok(())
    }
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
            warn!("LUSER_ENCRYPTION_KEY 未设置, 使用默认生成秘钥键");
            EncryptionManager::generate_base64_key(EncryptionAlgorithm::Aes256Gcm)
                .unwrap_or_else(|_| base64::encode(vec![0u8; 32]))
        });

        let encryption_manager =
            EncryptionManager::from_base64_key(EncryptionAlgorithm::Aes256Gcm, &base64_key)?;
        *global_encryptor = Some(ConfigEncryptor::new(encryption_manager));
    }
    Ok(())
}
/// 初始化全局加密器（带密钥管理）
pub fn init_global_encryptor_with_key_manager(
    rotation_interval: std::time::Duration,
) -> ConfigResult<()> {
    let mut global_encryptor = GLOBAL_ENCRYPTOR.write();
    if global_encryptor.is_none() {
        // 从环境变量获取加密密钥
        let base64_key = std::env::var(ENCRYPTION_KEY_ENV).unwrap_or_else(|_| {
            warn!("LUSER_ENCRYPTION_KEY 未设置, 使用默认生成秘钥键");
            EncryptionManager::generate_base64_key(EncryptionAlgorithm::Aes256Gcm)
                .unwrap_or_else(|_| base64::encode(vec![0u8; 32]))
        });

        let key = STANDARD.decode(&base64_key).map_err(|e| {
            ConfigError::EncryptionError(format!("解码 base64 密钥失败: {}", e))
        })?;

        let encryptor = ConfigEncryptor::new_with_key_manager(
            EncryptionAlgorithm::Aes256Gcm,
            key,
            rotation_interval,
        )?;

        *global_encryptor = Some(encryptor);
    }
    Ok(())
}
/// 获取全局加密器
pub fn get_global_encryptor() -> ConfigResult<ConfigEncryptor> {
    let global_encryptor = GLOBAL_ENCRYPTOR.read();
    global_encryptor
        .as_ref()
        .cloned()
        .ok_or_else(|| ConfigError::NotInitialized("全局加密器未初始化".to_string()))
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConfigManager;
    use std::{env, time::Duration};
    use tempfile::NamedTempFile;
    /// 测试密钥生成
    #[test]
    fn test_key_generation() -> ConfigResult<()> {
        // 1. 测试AES-256-GCM密钥生成
        let aes_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        assert_eq!(aes_key.len(), 32); // AES-256使用32字节密钥

        let aes_base64 = EncryptionManager::generate_base64_key(EncryptionAlgorithm::Aes256Gcm)?;
        let decoded_aes = STANDARD.decode(&aes_base64)?;
        assert_eq!(decoded_aes.len(), 32);

        // 2. 测试算法字符串转换
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.as_str(), "aes-256-gcm");
        assert_eq!(
            EncryptionAlgorithm::from_str("aes-256-gcm"),
            Some(EncryptionAlgorithm::Aes256Gcm)
        );
        assert_eq!(EncryptionAlgorithm::from_str("invalid"), None);

        Ok(())
    }

    /// 测试基本加密解密
    #[test]
    fn test_basic_encryption_decryption() -> ConfigResult<()> {
        // 生成测试密钥
        let test_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;

        // 创建加密管理器
        let manager = EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, test_key)?;

        // 测试数据
        let plaintext = "这是一个需要加密的敏感配置值，包含密码和密钥信息";

        // 加密
        let encrypted = manager.encrypt_string(plaintext)?;
        println!("加密后的数据: {}", encrypted);

        // 解密
        let decrypted = manager.decrypt_string(&encrypted)?;
        println!("解密后的数据: {}", decrypted);

        // 验证
        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted, plaintext);

        // 验证非加密数据
        let non_encrypted = "plain text";
        assert!(!manager.is_encrypted(non_encrypted));

        Ok(())
    }

    /// 测试AES-GCM加密解密
    #[test]
    fn test_aes_gcm_encryption() -> ConfigResult<()> {
        // 使用固定密钥进行测试
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let manager = EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, key)?;

        // 测试各种长度的数据
        let test_cases = vec![
            "",                             // 空字符串
            "a",                            // 单个字符
            "short",                        // 短字符串
            "这是一个中等长度的测试字符串", // 中文
            "This is a very long test string that contains multiple words and special characters: !@#$%^&*()_+{}|:\"<>?~`-=[]\\;',./", // 长字符串带特殊字符
        ];

        for (i, plaintext) in test_cases.iter().enumerate() {
            println!("测试用例 {}: 长度 = {}", i, plaintext.len());

            // 加密
            let encrypted = manager.encrypt_string(plaintext)?;

            // 验证密文不是明文
            assert_ne!(&encrypted, plaintext);

            // 解密
            let decrypted = manager.decrypt_string(&encrypted)?;

            // 验证解密结果
            assert_eq!(&decrypted, plaintext);

            // 验证是否能检测为加密数据
            assert!(manager.is_encrypted(&encrypted));
        }

        Ok(())
    }

    #[test]
    fn test_encryption_decryption() -> ConfigResult<()> {
        // 设置测试环境变量
        unsafe { env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

        // 创建加密管理器
        let encryption_manager =
            EncryptionManager::from_env(EncryptionAlgorithm::Aes256Gcm, "LUSER_ENCRYPTION_KEY")?;

        let encryptor = ConfigEncryptor::new(encryption_manager);

        // 测试字符串加密解密
        let plaintext = "my_secret_password";
        let encrypted = encryptor.encrypt_config_value(
            "test.password",
            plaintext,
            ConfigSecurityLevel::Sensitive,
        )?;

        assert!(encrypted.starts_with("ENC[sensitive:"));
        assert!(encrypted.ends_with(']'));

        let decrypted = encryptor.decrypt_config_value("test.password", &encrypted)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_config_encryption() -> ConfigResult<()> {
        // 设置测试环境变量
        unsafe { std::env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

        // 创建测试配置
        let mut config = crate::AppConfig::default();
        config.database.url = "postgres://user:password@localhost:5432/db".to_string();
        config.redis.password = Some("redis_password".to_string());
        config.jwt.secret = "jwt_secret_key".to_string();

        // 初始化加密器
        init_global_encryptor()?;
        let encryptor = get_global_encryptor()?;

        // 保存原始值
        let original_db_url = config.database.url.clone();
        let original_redis_password = config.redis.password.clone();
        let original_jwt_secret = config.jwt.secret.clone();

        println!("\n=== 开始测试 ===");
        println!("原始数据库URL: {}", original_db_url);

        // 测试1: 单独测试数据库URL加密/解密
        println!("\n1. 测试数据库URL加密/解密:");
        let encrypted_url = encryptor.encrypt_database_url(&original_db_url)?;
        println!("加密后URL: {}", encrypted_url);

        let decrypted_url = encryptor.decrypt_database_url(&encrypted_url)?;
        println!("解密后URL: {}", decrypted_url);
        assert_eq!(decrypted_url, original_db_url, "数据库URL解密失败");

        // 测试2: 加密整个配置
        println!("\n2. 加密整个配置:");
        encryptor.encrypt_config(&mut config)?;

        println!("加密后数据库URL: {}", config.database.url);

        // 验证配置已加密
        assert_ne!(config.database.url, original_db_url);
        assert!(
            config.database.url.contains("ENC%5B")
                || encryptor.is_encrypted_value(&config.database.url)
        );

        if let Some(ref redis_password) = config.redis.password {
            assert!(redis_password.starts_with("ENC[sensitive:"));
        }

        assert!(config.jwt.secret.starts_with("ENC[secret:"));

        // 测试3: 解密整个配置
        println!("\n3. 解密整个配置:");
        encryptor.decrypt_config(&mut config)?;

        println!("解密后数据库URL: {}", config.database.url);

        // 验证配置已正确解密
        assert_eq!(config.database.url, original_db_url, "数据库URL解密失败");
        assert_eq!(
            config.redis.password, original_redis_password,
            "Redis密码解密失败"
        );
        assert_eq!(config.jwt.secret, original_jwt_secret, "JWT密钥解密失败");

        println!("\n=== 测试通过 ===");

        Ok(())
    }

    #[test]
    fn test_database_url_encryption_decryption() -> ConfigResult<()> {
        unsafe { std::env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

        init_global_encryptor()?;
        let encryptor = get_global_encryptor()?;

        let test_cases = vec![
            // (url, should_be_encrypted)
            ("postgres://user:password@localhost:5432/db", true),
            ("postgres://admin:admin123@localhost:5432/testdb", true),
            ("mysql://user:pass%40word@localhost:3306/mydb", true), // @编码为%40
            ("postgres://user:pass%2Fword@localhost:5432/db", true), // /编码为%2F
            ("postgres://user:pass%3Aword@localhost:5432/db", true), // :编码为%3A
            ("postgres://user:@localhost:5432/db", false),          // 空密码，不应加密
            ("postgres://user@localhost:5432/db", false),           // 无密码，不应加密
        ];

        for (i, (url, should_be_encrypted)) in test_cases.iter().enumerate() {
            println!("\n测试 {}: {}", i + 1, url);

            // 加密
            let encrypted = encryptor.encrypt_database_url(url)?;
            println!("加密后: {}", encrypted);

            if *should_be_encrypted {
                assert_ne!(encrypted, *url, "URL应该被加密但未被加密");
            }

            // 解密
            let decrypted = encryptor.decrypt_database_url(&encrypted)?;
            println!("解密后: {}", decrypted);

            // 验证解密后与原始相同
            assert_eq!(decrypted, *url, "测试 {} 失败: URL解密后不匹配", i + 1);
        }

        println!("\n所有数据库URL加密/解密测试通过！");
        Ok(())
    }

    #[test]
    fn test_config_manager_encryption() -> ConfigResult<()> {
        unsafe { env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

        // 创建临时配置文件
        let mut temp_file = NamedTempFile::new()?;
        let config_content = r#"
            [database]
            url = "postgres://user:password@localhost:5432/db"
            
            [redis]
            password = "redis_pass"
            
            [jwt]
            secret = "jwt_secret"
        "#;

        std::fs::write(temp_file.path(), config_content)?;

        // 使用ConfigManager加载配置
        let mut manager = ConfigManager::new()?;

        // 获取配置并验证
        let config = manager.get_config();

        // 导出加密配置
        let export_path = temp_file.path().with_extension("encrypted.toml");
        manager.export_to_file(&export_path)?;

        // 读取导出的文件验证加密
        let exported_content = std::fs::read_to_string(&export_path)?;
        assert!(exported_content.contains("ENC["));

        // 导入加密配置
        manager.import_from_file(&export_path)?;

        Ok(())
    }
    /// 测试密钥轮换
    #[test]
    fn test_key_rotation() -> ConfigResult<()> {
        // 创建带密钥管理的加密管理器
        let initial_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        let rotation_interval = Duration::from_secs(3600); // 1小时

        let manager = EncryptionManager::new_with_key_manager(
            EncryptionAlgorithm::Aes256Gcm,
            initial_key.clone(),
            rotation_interval,
        )?;

        // 获取密钥管理器
        let key_manager_ref = manager
            .key_manager()
            .expect("Key manager should be initialized");

        // 获取初始密钥
        let current_key = key_manager_ref.read().get_current_key();
        assert_eq!(current_key, initial_key);

        // 测试数据
        let plaintext = "需要加密的敏感数据";

        // 用当前密钥加密
        let encrypted1 = manager.encrypt_string(plaintext)?;
        println!("用初始密钥加密的数据: {}", encrypted1);

        // 轮换密钥
        let new_key_id = manager.rotate_key()?;
        println!("新密钥ID: {}", new_key_id);

        // 验证密钥已更新
        let updated_key = key_manager_ref.read().get_current_key();
        assert_ne!(updated_key, initial_key);
        println!(
            "初始密钥长度: {}, 新密钥长度: {}",
            initial_key.len(),
            updated_key.len()
        );

        // 用新密钥加密
        let encrypted2 = manager.encrypt_string(plaintext)?;
        println!("用新密钥加密的数据: {}", encrypted2);

        // 验证两个密文不同（由于不同密钥和nonce）
        assert_ne!(encrypted1, encrypted2);

        // 用新密钥解密旧数据（应该失败，因为密钥不同）
        let decrypt_old_result = manager.decrypt_string(&encrypted1);
        println!("用新密钥解密旧数据的结果: {:?}", decrypt_old_result);
        assert!(decrypt_old_result.is_err(), "用新密钥解密旧数据应该失败");

        // 用历史密钥解密旧数据
        let decrypted_with_history = key_manager_ref
            .read()
            .decrypt_with_historical_keys(&STANDARD.decode(&encrypted1)?, &manager)?;

        let decrypted_str = String::from_utf8(decrypted_with_history).expect("decrypted_str String::from_utf8");
        assert_eq!(decrypted_str, plaintext);
        println!("用历史密钥成功解密旧数据");

        // 用当前密钥解密新数据
        let decrypted2 = manager.decrypt_string(&encrypted2)?;
        assert_eq!(decrypted2, plaintext);
        println!("用当前密钥成功解密新数据");

        Ok(())
    }

    /// 测试配置加密器
    #[test]
    fn test_config_encryptor() -> ConfigResult<()> {
       // 创建加密管理器
    let key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
    let manager = EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, key)?;
    let encryptor = ConfigEncryptor::new(manager);
    
    // 测试不同安全级别的加密
    let test_values = vec![
        ("database.password", "mysecretpassword", ConfigSecurityLevel::Sensitive),
        ("jwt.secret", "supersecretjwtkey", ConfigSecurityLevel::Secret),
        ("api.key", "publicapikey", ConfigSecurityLevel::Public),
        ("internal.token", "internal_token_123", ConfigSecurityLevel::Internal),
    ];
    
    for (key, value, security_level) in test_values.clone() {
        println!("测试配置项: key={}, level={:?}", key, security_level);
        
        // 加密
        let encrypted = encryptor.encrypt_config_value(key, value, security_level)?;
        println!("加密后: {}", encrypted);
        
        // 根据安全级别判断是否应该加密
        match security_level {
            ConfigSecurityLevel::Sensitive | ConfigSecurityLevel::Secret => {
                // 对于敏感和机密级别，应该被加密
                assert!(encryptor.is_encrypted_value(&encrypted),
                       "{} 应该被加密，但未被识别为加密值", key);
                
                // 解密
                let decrypted = encryptor.decrypt_config_value(key, &encrypted)?;
                println!("解密后: {}", decrypted);
                
                // 验证解密结果
                assert_eq!(decrypted, value,
                          "解密后的值不匹配，key={}", key);
            }
            ConfigSecurityLevel::Public | ConfigSecurityLevel::Internal => {
                // 对于公共和内部级别，不应该被加密（默认配置）
                assert_eq!(encrypted, value,
                          "未加密的值应该保持不变，key={}", key);
                assert!(!encryptor.is_encrypted_value(&encrypted),
                       "{} 不应该被识别为加密值", key);
            }
        }
    }
    
    // 测试修改安全级别配置后的行为
    println!("\n=== 测试修改安全级别配置 ===");
    encryptor.set_security_levels(vec![
        ConfigSecurityLevel::Public,
        ConfigSecurityLevel::Internal,
        ConfigSecurityLevel::Sensitive,
        ConfigSecurityLevel::Secret,
    ]);
    
    // 现在所有级别都应该加密
    for (key, value, security_level) in test_values {
        println!("测试配置项（修改后）: key={}, level={:?}", key, security_level);
        
        // 加密
        let encrypted = encryptor.encrypt_config_value(key, value, security_level)?;
        println!("加密后: {}", encrypted);
        
        // 现在所有级别都应该被加密
        assert!(encryptor.is_encrypted_value(&encrypted),
               "{} 应该被加密，但未被识别为加密值", key);
        
        // 解密
        let decrypted = encryptor.decrypt_config_value(key, &encrypted)?;
        println!("解密后: {}", decrypted);
        
        // 验证解密结果
        assert_eq!(decrypted, value,
                  "解密后的值不匹配，key={}", key);
    }
    
    Ok(())
    }

    /// 测试批量加密解密
    #[test]
    fn test_batch_encryption() -> ConfigResult<()> {
        let key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        let manager = EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, key)?;
        let encryptor = ConfigEncryptor::new(manager);

        // 准备批量数据
        let values_to_encrypt = vec![
            ("db.password", "dbpass123", ConfigSecurityLevel::Sensitive),
            (
                "redis.password",
                "redispass456",
                ConfigSecurityLevel::Sensitive,
            ),
            ("api.secret", "apisecret789", ConfigSecurityLevel::Secret),
        ];

        // 批量加密
        let encrypted_results = encryptor.encrypt_config_values(&values_to_encrypt)?;
        assert_eq!(encrypted_results.len(), 3);

        // 转换格式用于批量解密
        let encrypted_pairs: Vec<(&str, &str)> = encrypted_results
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        // 批量解密
        let decrypted_results = encryptor.decrypt_config_values(&encrypted_pairs)?;
        assert_eq!(decrypted_results.len(), 3);

        // 验证解密结果
        for ((original_key, original_value, _), (decrypted_key, decrypted_value)) in
            values_to_encrypt.iter().zip(decrypted_results.iter())
        {
            assert_eq!(original_key, decrypted_key);
            assert_eq!(original_value, decrypted_value);
        }

        Ok(())
    }
    /// 测试Nonce生成器
    #[test]
    fn test_nonce_generators() -> ConfigResult<()> {
        // 测试安全Nonce生成器
        let secure_generator = SecureNonceGenerator;
        let nonce1 = secure_generator.generate_nonce(12);
        let nonce2 = secure_generator.generate_nonce(12);
        
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2); // 随机生成应该不同
        
        // 测试时间戳Nonce生成器
        let timestamp_generator = TimestampNonceGenerator;
        let nonce3 = timestamp_generator.generate_nonce(12);
        let nonce4 = timestamp_generator.generate_nonce(12);
        
        assert_eq!(nonce3.len(), 12);
        assert_eq!(nonce4.len(), 12);
        // 时间戳可能相同（如果在同一纳秒内），但通常不同
        
        Ok(())
    }
    /// 测试数据完整性验证
    #[test]
    fn test_data_integrity() -> ConfigResult<()> {
        let key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        let manager = EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, key)?;
        
        // 测试数据
        let data1 = b"Important configuration data";
        let data2 = b"Modified configuration data";
        
        // 计算哈希
        let hash1 = manager.hash_data(data1)?;
        let hash2 = manager.hash_data(data2)?;
        
        println!("Data1哈希: {}", hash1);
        println!("Data2哈希: {}", hash2);
        
        // 验证相同数据的哈希
        let same_hash = manager.hash_data(data1)?;
        assert_eq!(hash1, same_hash);
        
        // 验证不同数据的哈希不同
        assert_ne!(hash1, hash2);
        
        // 验证完整性
        assert!(manager.verify_integrity(data1, &hash1)?);
        assert!(!manager.verify_integrity(data1, &hash2)?);
        assert!(!manager.verify_integrity(data2, &hash1)?);
        
        Ok(())
    }
   /// 测试密钥管理器的导入导出
    #[test]
    fn test_key_manager_import_export() -> ConfigResult<()> {
        // 创建初始密钥管理器
        let initial_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        let key_manager1 = KeyManager::new(
            initial_key.clone(),
            Duration::from_secs(3600),
        )?;
        
        // 执行几次密钥轮换
        key_manager1.rotate_key()?;
        key_manager1.rotate_key()?;
        
        // 创建导出密钥
        let export_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        
        // 导出密钥历史
        let encrypted_history = key_manager1.export_key_history(&export_key)?;
        assert!(!encrypted_history.is_empty());
        
        // 导入到新的密钥管理器
        let mut key_manager2 = KeyManager::new(
            EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?,
            Duration::from_secs(7200),
        )?;
        
        key_manager2.import_key_history(&encrypted_history, &export_key)?;
        
        // 验证两个密钥管理器有相同的活动密钥
        let key1 = key_manager1.get_current_key();
        let key2 = key_manager2.get_current_key();
        assert_eq!(key1, key2);
        
        // 验证密钥ID
        if let Some(active_entry1) = key_manager1.key_history.read().iter().find(|e| e.active) {
            if let Some(active_entry2) = key_manager2.key_history.read().iter().find(|e| e.active) {
                assert_eq!(active_entry1.key_id, active_entry2.key_id);
            }
        }
        
        Ok(())
    }
    /// 测试环境变量集成
    #[test]
    fn test_env_integration() -> ConfigResult<()> {
        // 生成测试密钥
        let test_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        let test_key_base64 = STANDARD.encode(&test_key);
        
        // 设置环境变量
        unsafe { std::env::set_var("TEST_ENCRYPTION_KEY", &test_key_base64) };
        
        // 从环境变量创建加密管理器
        let manager = EncryptionManager::from_env(EncryptionAlgorithm::Aes256Gcm, "TEST_ENCRYPTION_KEY")?;
        
        // 测试加密解密
        let plaintext = "data from env";
        let encrypted = manager.encrypt_string(plaintext)?;
        let decrypted = manager.decrypt_string(&encrypted)?;
        
        assert_eq!(decrypted, plaintext);
        
        // 清理环境变量
        unsafe { std::env::remove_var("TEST_ENCRYPTION_KEY") };
        
        // 测试不存在的环境变量
        let result = EncryptionManager::from_env(EncryptionAlgorithm::Aes256Gcm, "NONEXISTENT_ENV_VAR");
        assert!(result.is_err());
        
        Ok(())
    }
    /// 测试并发访问
    #[test]
    fn test_concurrent_access() -> ConfigResult<()> {
        use std::sync::Arc;
        use std::thread;
        
        let key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        let manager = Arc::new(EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, key)?);
        
        let mut handles = vec![];
        let plaintext = "concurrent test data";
        
        // 启动多个线程并发加密
        for i in 0..10 {
            let manager_clone = manager.clone();
            let plaintext_clone = plaintext.to_string();
            
            let handle = thread::spawn(move || {
                let encrypted = manager_clone.encrypt_string(&plaintext_clone);
                assert!(encrypted.is_ok());
                
                let decrypted = manager_clone.decrypt_string(&encrypted.unwrap());
                assert!(decrypted.is_ok());
                assert_eq!(decrypted.unwrap(), plaintext_clone);
                
                println!("线程 {} 完成", i);
            });
            
            handles.push(handle);
        }
        
        // 等待所有线程完成
        for handle in handles {
            handle.join().unwrap();
        }
        
        Ok(())
    }
}
