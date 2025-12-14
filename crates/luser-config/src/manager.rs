use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use std::path::Path;
use chrono::Utc;
use parking_lot::RwLock;
use sqlx::Postgres;
use tokio::sync::mpsc;
use tracing::{error, info};
use validator::Validate;

use crate::{AppConfig, ConfigDiff, ConfigError, ConfigLoader, ConfigMerger, ConfigPriority, ConfigResult, ConfigSecurityLevel, ConfigSourceInfo, ConfigSourceType, ConfigWatcher, DatabaseConfigWatcher, EncryptionAlgorithm, EncryptionManager, get_global_encryptor, init_global_encryptor, init_global_encryptor_with_key_manager};

/// 配置管理器
#[derive(Debug)]
pub struct ConfigManager {
    config: Arc<RwLock<AppConfig>>,
    loader: ConfigLoader,
    watcher: Option<ConfigWatcher>,
    dynamic_updates: Arc<RwLock<Vec<DynamicUpdate>>>,
     /// 加密管理器
    encryptor: Option<Arc<crate::encryption::ConfigEncryptor>>,
     /// 数据库监控器
    db_watcher: Option<DatabaseConfigWatcher>,
    /// 重载通道接收器
    reload_receiver: Option<mpsc::Receiver<()>>,
}
impl Clone for ConfigManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            loader: self.loader.clone(),
            watcher: None, // 不克隆 watcher
            dynamic_updates: self.dynamic_updates.clone(),
             encryptor: self.encryptor.clone(),
              db_watcher: None,
            reload_receiver: None,
        }
    }
}
/// 动态更新记录
#[derive(Debug, Clone)]
pub struct DynamicUpdate {
    pub timestamp: chrono::DateTime<Utc>,
    pub source: ConfigSourceType,
    pub priority: ConfigPriority,
    pub description: String,
    pub changes: ConfigDiff,
}

impl ConfigManager {
    /// 创建新的配置管理器（自动解密敏感配置）
    pub fn new() -> ConfigResult<Self> {
        Self::new_with_key_management(None)
    }
    /// 创建带密钥管理的配置管理器
    pub fn new_with_key_management(
        key_rotation_interval: Option<std::time::Duration>,
    ) -> ConfigResult<Self> {
        let mut loader = ConfigLoader::new();
        let config = loader.load()?;
        
        // 根据是否有密钥管理需求初始化加密器
        let encryptor = if let Some(interval) = key_rotation_interval {
            // 初始化带密钥管理的全局加密器
            init_global_encryptor_with_key_manager(interval)?;
            Some(Arc::new(get_global_encryptor()?))
        } else {
            // 初始化普通全局加密器
            init_global_encryptor()?;
            Some(Arc::new(get_global_encryptor()?))
        };
        
        // 解密敏感配置
        let mut decrypted_config = config.clone();
        if let Some(enc) = &encryptor {
            enc.decrypt_config(&mut decrypted_config)?;
        }
        
        // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;
        
        Ok(Self {
            config: Arc::new(RwLock::new(decrypted_config)),
            loader,
            watcher: None,
            dynamic_updates: Arc::new(RwLock::new(Vec::new())),
            encryptor,
            db_watcher: None,
            reload_receiver: None,
        })
    }

     /// 从指定环境创建配置管理器（自动解密敏感配置）
    pub fn with_environment(env: &str) -> ConfigResult<Self> {
       let mut loader = ConfigLoader::new();
        loader.set_environment(env);
        let config = loader.load()?;
        // 初始化全局加密器
        init_global_encryptor()?;
        let encryptor = Arc::new(get_global_encryptor()?);
        
        // 解密敏感配置
        let mut decrypted_config = config.clone();
        encryptor.decrypt_config(&mut decrypted_config)?;
        
        // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;
        
        Ok(Self {
            config: Arc::new(RwLock::new(decrypted_config)),
            loader,
            watcher: None,
            dynamic_updates: Arc::new(RwLock::new(Vec::new())),
            encryptor: Some(encryptor),
            db_watcher: None,
            reload_receiver: None,
        })
    }
    /// 创建带数据库连接的配置管理器
    pub fn with_database(env: &str, db_pool: sqlx::Pool<Postgres>) -> ConfigResult<Self> {
        let mut loader = ConfigLoader::new();
        loader.set_environment(env);
        loader.set_database_pool(db_pool);
        let config = loader.load()?;
        
        // 初始化全局加密器
        init_global_encryptor()?;
        let encryptor = Arc::new(get_global_encryptor()?);
        
        // 解密敏感配置
        let mut decrypted_config = config.clone();
        encryptor.decrypt_config(&mut decrypted_config)?;
        
        Ok(Self {
            config: Arc::new(RwLock::new(decrypted_config)),
            loader,
            watcher: None,
            dynamic_updates: Arc::new(RwLock::new(Vec::new())),
            encryptor: Some(encryptor),
            db_watcher: None,
            reload_receiver: None,
        })
    }
     /// 获取当前配置
    pub fn get_config(&self) -> AppConfig {
        self.config.read().clone()
    }
     /// 获取加密器
    pub fn encryptor(&self) -> Option<Arc<crate::encryption::ConfigEncryptor>> {
        self.encryptor.clone()
    }
    /// 启用密钥管理
    pub fn enable_key_management(&mut self, rotation_interval: std::time::Duration) -> ConfigResult<()> {
        if let Some(encryptor) = &mut self.encryptor {
            // 创建新的加密器实例（因为需要mut）
            let mut new_encryptor = (**encryptor).clone();
            new_encryptor.enable_key_management(rotation_interval)?;
            self.encryptor = Some(Arc::new(new_encryptor));
        } else {
            // 创建新的加密器
            let encryption_manager = EncryptionManager::new(
                EncryptionAlgorithm::Aes256Gcm,
                self.get_encryption_key()?,
            )?;
            let mut encryptor = crate::encryption::ConfigEncryptor::new(encryption_manager);
            encryptor.enable_key_management(rotation_interval)?;
            self.encryptor = Some(Arc::new(encryptor));
        }
        
        info!("Key management enabled with rotation interval: {:?}", rotation_interval);
        Ok(())
    }
   
    /// 获取加密密钥
    fn get_encryption_key(&self) -> ConfigResult<Vec<u8>> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        
        let base64_key = std::env::var(crate::ENCRYPTION_KEY_ENV)
            .map_err(|_| ConfigError::EncryptionError(
                "Encryption key not found in environment".to_string(),
            ))?;
            
        STANDARD.decode(&base64_key)
            .map_err(|e| ConfigError::EncryptionError(
                format!("Failed to decode encryption key: {}", e)
            ))
    }
    
     /// 轮换密钥
    pub fn rotate_key(&self) -> ConfigResult<String> {
        if let Some(encryptor) = &self.encryptor {
            if let Some(key_manager) = encryptor.key_manager() {
                let new_key_id = key_manager.write().rotate_key()?;
                info!("Encryption key rotated: {}", new_key_id);
                Ok(new_key_id)
            } else {
                Err(ConfigError::EncryptionError(
                    "Key management is not enabled".to_string(),
                ))
            }
        } else {
            Err(ConfigError::EncryptionError(
                "Encryptor not initialized".to_string(),
            ))
        }
    }
     /// 加密配置值
    pub fn encrypt_value(&self, key: &str, value: &str) -> ConfigResult<String> {
        if let Some(encryptor) = &self.encryptor {
            let security_level = self.determine_security_level(key);
            encryptor.encrypt_config_value(key, value, security_level)
        } else {
            Err(ConfigError::EncryptionError(
                "Encryptor not initialized".to_string(),
            ))
        }
    }
    /// 解密配置值
    pub fn decrypt_value(&self, key: &str, value: &str) -> ConfigResult<String> {
        if let Some(encryptor) = &self.encryptor {
            encryptor.decrypt_config_value(key, value)
        } else {
            Err(ConfigError::EncryptionError(
                "Encryptor not initialized".to_string(),
            ))
        }
    }

    /// 重新加载配置（自动解密敏感配置）
    pub fn reload(&mut self) -> ConfigResult<()> {
       info!("Reloading configuration");

        let old_config = self.config.read().clone();
        let new_config = self.loader.load()?;
        // 解密新配置
        let mut decrypted_new_config = new_config.clone();
        if let Some(encryptor) = &self.encryptor {
            encryptor.decrypt_config(&mut decrypted_new_config)?;
        }
        // 计算配置差异
        let diff = ConfigMerger::diff_configs(
            &serde_json::to_value(&old_config).unwrap(),
            &serde_json::to_value(&decrypted_new_config).unwrap(),
        );
          if diff.has_changes() {
            info!("Configuration changes detected: {}", diff.summary());
            
            // 验证解密后的配置
            let validator = crate::validator::ConfigValidator::new();
            validator.validate(&decrypted_new_config)?;
            // 记录动态更新
            let update = DynamicUpdate {
                timestamp: Utc::now(),
                source: ConfigSourceType::File,
                priority: ConfigPriority::EnvironmentFile,
                description: "Reload from all sources".to_string(),
                changes: diff,
            };
             self.dynamic_updates.write().push(update);
             // 更新配置
            *self.config.write() = decrypted_new_config;
            
            info!("Configuration reloaded successfully");
        } else {
            info!("No configuration changes detected");
        }
        
        Ok(())
    }
    /// 重新加载数据库配置
    pub fn reload_database_config(&mut self) -> ConfigResult<()> {
        info!("Reloading database configuration");
        
        self.loader.reload_database_config()?;
        self.reload()?;
        
        Ok(())
    }
    /// 动态更新配置（最高优先级）
    pub fn update_config_dynamic(&self, updates: HashMap<String, serde_json::Value>) -> ConfigResult<()> {
        info!("Updating configuration dynamically");
        
        let old_config = self.config.read().clone();
        let old_value = serde_json::to_value(&old_config)
            .map_err(|e| ConfigError::SerializationFailed(format!("Failed to serialize config: {}", e)))?;
        
        // 应用更新
        let mut new_value = old_value.clone();
        let updates_value = serde_json::to_value(updates)
            .map_err(|e| ConfigError::SerializationFailed(format!("Failed to serialize updates: {}", e)))?;
        
        ConfigMerger::deep_merge(&mut new_value, &updates_value, false);
        
        // 计算差异
        let diff = ConfigMerger::diff_configs(&old_value, &new_value);
        
        if diff.has_changes() {
            // 反序列化为AppConfig
            let new_config: AppConfig = serde_json::from_value(new_value)
                .map_err(|e| ConfigError::DeserializationFailed(format!("Failed to deserialize updated config: {}", e)))?;
            
            // 验证新配置
            let validator = crate::validator::ConfigValidator::new();
            validator.validate(&new_config)?;
            
            // 记录动态更新
            let update = DynamicUpdate {
                timestamp: Utc::now(),
                source: ConfigSourceType::Runtime,
                priority: ConfigPriority::Runtime,
                description: "Dynamic runtime update".to_string(),
                changes: diff.clone(),
            };
            
            self.dynamic_updates.write().push(update);
            
            // 更新配置
            *self.config.write() = new_config;
            
            info!("Configuration updated dynamically: {}", diff.summary());
        } else {
            info!("No configuration changes in dynamic update");
        }
        
        Ok(())
    }
    /// 更新单个配置值
    pub fn update_config_value<T: serde::Serialize>(&self, path: &str, value: T) -> ConfigResult<()> {
        let value_json = serde_json::to_value(value)
            .map_err(|e| ConfigError::SerializationFailed(format!("Failed to serialize value: {}", e)))?;
        
        let mut updates = HashMap::new();
        
        // 将点分隔的路径转换为嵌套的HashMap
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = &mut updates;
        
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // 最后一个部分，设置值
                current.insert(part.to_string(), value_json.clone());
            } else {
                // 中间部分，创建嵌套
                let nested: HashMap<String, serde_json::Value> = HashMap::new();
                current.insert(part.to_string(), serde_json::to_value(nested).unwrap());
                // TODO 注意：这里简化处理，实际应该递归构建嵌套结构
            }
        }
        
        self.update_config_dynamic(updates)
    }
    /// 更新配置
    pub fn update_config<F>(&self, updater: F) -> ConfigResult<()>
    where
        F: FnOnce(&mut AppConfig),
    {
        let mut config = self.config.write();
        updater(&mut config);
        Ok(())
    }
    
    /// 获取配置值
    pub fn get_value<T: serde::de::DeserializeOwned>(&self, key: &str) -> ConfigResult<T> {
        let config = self.config.read();
        
        // 尝试从扩展配置中获取
        if let Some(value) = config.extensions.get(key) {
            return serde_json::from_value(value.clone())
                .map_err(|e| ConfigError::ValueNotFound(format!("Failed to deserialize value for key {}: {}", key, e)));
        }
        
        // TODO 这里可以实现从主配置中获取值的逻辑
        // 由于配置结构复杂，需要实现特定的解析逻辑
        
        Err(ConfigError::ValueNotFound(format!("Config key not found: {}", key)))
    }
    
    /// 设置配置值
    pub fn set_value<T: serde::Serialize>(&self, key: &str, value: T) -> ConfigResult<()> {
        let mut config = self.config.write();
        config.set_extension(key, value);
        Ok(())
    }
    
    /// 导出配置到文件（自动加密敏感配置）
    pub fn export_to_file<P: AsRef<Path>>(&self, path: P) -> ConfigResult<()> {
         let config = self.config.read().clone();
        
       // 加密敏感配置
        let mut encrypted_config = config.clone();
        if let Some(encryptor) = &self.encryptor {
            encryptor.encrypt_config(&mut encrypted_config)?;
        }
        
        let toml = toml::to_string_pretty(&encrypted_config)
            .map_err(|e| ConfigError::SerializationFailed(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(path, toml)
            .map_err(|e| ConfigError::IoError(format!("Failed to write config file: {}", e)))?;
        
        info!("Configuration exported to file with encryption");
        Ok(())
    }
    
     /// 导入配置从文件（自动解密敏感配置）
    pub fn import_from_file<P: AsRef<Path>>(&self, path: P) -> ConfigResult<()> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(format!("Failed to read config file: {}", e)))?;
        
        let new_config: AppConfig = toml::from_str(&content)
            .map_err(|e| ConfigError::DeserializationFailed(format!("Failed to deserialize config: {}", e)))?;
        
        // 解密敏感配置
        let mut decrypted_config = new_config.clone();
        if let Some(encryptor) = &self.encryptor {
            encryptor.decrypt_config(&mut decrypted_config)?;
        }
        
        // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;
        
        *self.config.write() = decrypted_config;
        
        info!("Configuration imported from file and decrypted");
        Ok(())
    }
    
    /// 验证配置
    pub fn validate(&self) -> ConfigResult<()> {
        let config = self.config.read();
        config.validate()
            .map_err(|e| ConfigError::ValidationFailed(format!("Config validation failed: {}", e)))?;
        
        Ok(())
    }
    
    /// 获取配置源信息
    pub fn get_source_info(&self) -> Vec<ConfigSourceInfo> {
        self.loader.get_source_info()
    }
    /// 获取动态更新历史
    pub fn get_dynamic_update_history(&self, limit: usize) -> Vec<DynamicUpdate> {
        let updates = self.dynamic_updates.read();
        updates.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
    /// 启动配置监控
    pub fn start_watching(&mut self) -> ConfigResult<()> {
        if self.watcher.is_none() {
            let mut watcher = ConfigWatcher::new(
                self.config.clone(), 
                self.loader.config_dir.clone()
            )?;
            watcher.start()?;
            
            // 获取重载通道接收器
            self.reload_receiver = watcher.get_reload_receiver();
            
            self.watcher = Some(watcher);
            info!("Configuration watcher started");
            
            // 启动重载监听任务
            if let Some(reload_receiver) = self.reload_receiver.take() {
                self.start_reload_listener(reload_receiver)?;
            }
        }
        
        Ok(())
    }
     /// 启动重载监听任务
    fn start_reload_listener(&mut self, mut receiver: mpsc::Receiver<()>) -> ConfigResult<()> {
        let mut manager = self.clone();
        
        tokio::spawn(async move {
            while let Some(_) = receiver.recv().await {
                info!("Received reload signal from file watcher");
                if let Err(e) = manager.reload() {
                    error!("Failed to reload configuration: {}", e);
                }
            }
        });
        
        Ok(())
    }

     /// 停止配置监控
    pub fn stop_watching(&mut self) {
        if let Some(watcher) = &mut self.watcher {
            watcher.stop();
            info!("Configuration watcher stopped");
        }
        self.watcher = None;
    }
     /// 启动数据库配置监控
    pub async fn start_database_watching(&mut self, check_interval: Duration) -> ConfigResult<()> {
        if self.db_watcher.is_none() {
            let manager = Arc::new(RwLock::new(self.clone()));
            let db_watcher = DatabaseConfigWatcher::new(manager, check_interval);
            db_watcher.start().await?;
            self.db_watcher = Some(db_watcher);
            info!("Database configuration watcher started");
        }
        
        Ok(())
    }
    /// 停止数据库配置监控
    pub fn stop_database_watching(&mut self) {
        if let Some(db_watcher) = &self.db_watcher {
            db_watcher.stop();
            info!("Database configuration watcher stopped");
        }
        self.db_watcher = None;
    }
     /// 启动自动重载任务
    pub async fn start_auto_reload_task(
        &self,
        check_interval: Duration,
    ) -> ConfigResult<()> {
        let manager = Arc::new(RwLock::new(self.clone()));
        ConfigWatcher::start_auto_reload(manager, check_interval).await
    }
    
    /// 检查配置是否需要重新加载
    pub fn should_reload(&self, interval_seconds: u64) -> bool {
        self.loader.should_reload(interval_seconds)
    }
    /// 检查配置是否已加载
    pub fn is_loaded(&self) -> bool {
        !self.config.read().server.host.is_empty()
    }
    /// 获取配置值的加密版本
    pub fn get_encrypted_value(&self, key: &str) -> ConfigResult<String> {
        
        // 根据key路径获取配置值
        let value = self.get_value_by_path(key)?;
        
        // 加密值
        let encryptor = get_global_encryptor()?;
        
        // 根据key确定安全级别
        let security_level = self.determine_security_level(key);
        
        encryptor.encrypt_config_value(key, &value, security_level)
    }
    
    /// 根据路径获取配置值
    fn get_value_by_path(&self, path: &str) -> ConfigResult<String> {
        let config = self.config.read();
        let parts: Vec<&str> = path.split('.').collect();
        
        match parts.as_slice() {
            ["database", "url"] => Ok(config.database.url.clone()),
            ["redis", "password"] => Ok(config.redis.password.clone().unwrap_or_default()),
            ["jwt", "secret"] => Ok(config.jwt.secret.clone()),
            ["encryption", "key"] => Ok(config.encryption.key.clone()),
            // 添加更多路径匹配...
            _ => {
                // 尝试从扩展配置中获取
                if let Some(value) = config.extensions.get(path) {
                    if let serde_json::Value::String(s) = value {
                        Ok(s.clone())
                    } else {
                        Ok(value.to_string())
                    }
                } else {
                    Err(ConfigError::ValueNotFound(format!("Config path not found: {}", path)))
                }
            }
        }
    }
    
    /// 根据key确定安全级别
    fn determine_security_level(&self, key: &str) -> ConfigSecurityLevel {
        if key.contains("secret") || key.contains("key") || key.contains("token") {
            ConfigSecurityLevel::Secret
        } else if key.contains("password") || key.contains("credential") {
            ConfigSecurityLevel::Sensitive
        } else if key.contains("access_key") || key.contains("api_key") {
            ConfigSecurityLevel::Internal
        } else {
            ConfigSecurityLevel::Public
        }
    }
    /// 获取配置优先级摘要
    pub fn get_priority_summary(&self) -> HashMap<ConfigPriority, usize> {
        let sources = self.loader.get_source_info();
        let mut summary = HashMap::new();
        
        for source in sources {
            *summary.entry(source.priority).or_insert(0) += 1;
        }
        
        summary
    }
    /// 导出合并后的配置
    pub fn export_merged_config(&self) -> ConfigResult<String> {
        let config = self.config.read();
        let toml = toml::to_string_pretty(&*config)
            .map_err(|e| ConfigError::SerializationFailed(format!("Failed to serialize config: {}", e)))?;
        
        Ok(toml)
    }
    
    /// 导入并合并配置
    pub fn import_and_merge_config(&self, toml_config: &str) -> ConfigResult<()> {
        let imported_config: AppConfig = toml::from_str(toml_config)
            .map_err(|e| ConfigError::DeserializationFailed(format!("Failed to deserialize imported config: {}", e)))?;
        
        let old_config = self.config.read().clone();
        
        // 合并配置
        let mut merged_config = old_config.clone();
        
        // 这里实现自定义的合并逻辑
        // 简化处理：深度合并
        let old_value = serde_json::to_value(&old_config)?;
        let imported_value = serde_json::to_value(&imported_config)?;
        let mut merged_value = old_value.clone();
        
        ConfigMerger::deep_merge(&mut merged_value, &imported_value, false);
        
        let merged_config: AppConfig = serde_json::from_value(merged_value)?;
        
        // 验证合并后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&merged_config)?;
        
        // 更新配置
        *self.config.write() = merged_config;
        
        info!("Configuration imported and merged successfully");
        
        Ok(())
    }
}

// 全局配置实例
lazy_static::lazy_static! {
    static ref GLOBAL_CONFIG: parking_lot::RwLock<Option<ConfigManager>> = parking_lot::RwLock::new(None);
}

/// 初始化全局配置
pub fn init_global_config() -> ConfigResult<()> {
    let mut global_config = GLOBAL_CONFIG.write();
    if global_config.is_none() {
        *global_config = Some(ConfigManager::new()?);
    }
    Ok(())
}

/// 初始化全局配置（指定环境）
pub fn init_global_config_with_env(env: &str) -> ConfigResult<()> {
    let mut global_config = GLOBAL_CONFIG.write();
    if global_config.is_none() {
        *global_config = Some(ConfigManager::with_environment(env)?);
    }
    Ok(())
}

/// 获取全局配置
pub fn get_global_config() -> ConfigResult<ConfigManager> {
    let global_config = GLOBAL_CONFIG.read();
    global_config.as_ref()
        .cloned()
        .ok_or_else(|| ConfigError::NotInitialized("Global config not initialized".to_string()))
}

/// 重新加载全局配置
pub fn reload_global_config() -> ConfigResult<()> {
    let mut global_config = GLOBAL_CONFIG.write();
    if let Some(config) = global_config.as_mut() {
        config.reload()
    } else {
        Err(ConfigError::NotInitialized("Global config not initialized".to_string()))
    }
}

/// 便捷函数：加载配置
pub fn load_config() -> ConfigResult<AppConfig> {
    Ok(get_global_config()?.get_config())
}

/// 便捷函数：获取配置值
pub fn get_config<T: serde::de::DeserializeOwned>(key: &str) -> ConfigResult<T> {
    get_global_config()?.get_value(key)
}

/// 便捷函数：设置配置值
pub fn set_config<T: serde::Serialize>(key: &str, value: T) -> ConfigResult<()> {
    get_global_config()?.set_value(key, value)
}