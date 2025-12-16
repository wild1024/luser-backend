use chrono::Utc;
use parking_lot::RwLock;
use sqlx::Postgres;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use validator::Validate;

use crate::{
    AppConfig, ConfigDiff, ConfigError, ConfigLoader, ConfigMerger, ConfigPriority, ConfigResult, ConfigSecurityLevel, ConfigSourceInfo, ConfigSourceType, ConfigWatcher, DEFAULT_CONFIG_PATH, DatabaseConfigLoader, DatabaseConfigWatcher, EncryptionAlgorithm, EncryptionManager, KeyRotationWatcher, get_global_encryptor, init_global_encryptor, init_global_encryptor_with_key_manager
};

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
     /// 密钥轮换监控器
    key_rotation_watcher: Option<KeyRotationWatcher>,
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
            key_rotation_watcher: None,

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
            key_rotation_watcher: None,
        })
    }
    /// 从指定环境创建配置管理器（自动解密敏感配置）
    pub fn with_environment(env: &str) -> ConfigResult<Self> {
         Self::with_env_and_key_management(env,None)
    }
    /// 从指定环境创建带密钥管理的配置管理器（自动解密敏感配置）
    pub fn with_env_and_key_management(
        env: &str,
        key_rotation_interval: Option<std::time::Duration>,
    ) -> ConfigResult<Self> {
        let mut loader = ConfigLoader::new();
        loader.set_environment(env);
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
            key_rotation_watcher: None,
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
            key_rotation_watcher: None,
        })
    }
    /// 创建带数据库连接的配置管理器
    pub async fn with_database_async(
        env: &str,
        db_pool: sqlx::Pool<Postgres>,
    ) -> ConfigResult<Self> {
        let mut loader = ConfigLoader::new();
        loader.set_environment(env);
        loader.set_database_pool(db_pool);

        // 使用异步加载
        let config = loader.load_async().await?;

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
            key_rotation_watcher: None,
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
    pub fn enable_key_management(
        &mut self,
        rotation_interval: std::time::Duration,
    ) -> ConfigResult<()> {
        if let Some(encryptor) = &mut self.encryptor {
            // 创建新的加密器实例（因为需要mut）
            let mut new_encryptor = (**encryptor).clone();
            new_encryptor.enable_key_management(rotation_interval)?;
            self.encryptor = Some(Arc::new(new_encryptor));
        } else {
            // 创建新的加密器
            let encryption_manager =
                EncryptionManager::new(EncryptionAlgorithm::Aes256Gcm, self.get_encryption_key()?)?;
            let mut encryptor = crate::encryption::ConfigEncryptor::new(encryption_manager);
            encryptor.enable_key_management(rotation_interval)?;
            self.encryptor = Some(Arc::new(encryptor));
        }

        info!(
            "启用密钥管理，并设定轮换间隔: {:?}",
            rotation_interval
        );
        Ok(())
    }

    /// 获取加密密钥
    fn get_encryption_key(&self) -> ConfigResult<Vec<u8>> {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let base64_key = std::env::var(crate::ENCRYPTION_KEY_ENV).map_err(|_| {
            ConfigError::EncryptionError("在环境中未找到加密密钥".to_string())
        })?;

        STANDARD.decode(&base64_key).map_err(|e| {
            ConfigError::EncryptionError(format!("解码加密密钥失败: {}", e))
        })
    }

    /// 轮换密钥
    pub fn rotate_key(&self) -> ConfigResult<String> {
        if let Some(encryptor) = &self.encryptor {
            if let Some(key_manager) = encryptor.key_manager() {
                let new_key_id = key_manager.write().rotate_key()?;
                info!("加密密钥已轮换： {}", new_key_id);
                Ok(new_key_id)
            } else {
                Err(ConfigError::EncryptionError(
                    "密钥管理未启用".to_string(),
                ))
            }
        } else {
            Err(ConfigError::EncryptionError(
                "加密器未初始化".to_string(),
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
                "加密器未初始化".to_string(),
            ))
        }
    }
    /// 解密配置值
    pub fn decrypt_value(&self, key: &str, value: &str) -> ConfigResult<String> {
        if let Some(encryptor) = &self.encryptor {
            encryptor.decrypt_config_value(key, value)
        } else {
            Err(ConfigError::EncryptionError(
                "加密器未初始化".to_string(),
            ))
        }
    }

    /// 重新加载配置（自动解密敏感配置）
    pub fn reload(&mut self) -> ConfigResult<()> {
        info!("重新加载配置");

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
            info!("检测到配置更改: {}", diff.summary());

            // 验证解密后的配置
            let validator = crate::validator::ConfigValidator::new();
            validator.validate(&decrypted_new_config)?;
            // 记录动态更新
            let update = DynamicUpdate {
                timestamp: Utc::now(),
                source: ConfigSourceType::File,
                priority: ConfigPriority::EnvironmentFile,
                description: "重新加载所有来源".to_string(),
                changes: diff,
            };
            self.dynamic_updates.write().push(update);
            // 更新配置
            *self.config.write() = decrypted_new_config;

            info!("配置已成功重新加载");
        } else {
            info!("未检测到配置更改");
        }

        Ok(())
    }
    /// 异步重新加载配置（自动解密敏感配置）
    pub async fn reload_async(&mut self) -> ConfigResult<()> {
        info!("异步重新加载配置");

        let old_config = self.config.read().clone();
        let new_config = self.loader.load_async().await?;

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
            info!("检测到配置更改: {}", diff.summary());

            // 验证解密后的配置
            let validator = crate::validator::ConfigValidator::new();
            validator.validate(&decrypted_new_config)?;

            // 记录动态更新
            let update = DynamicUpdate {
                timestamp: Utc::now(),
                source: ConfigSourceType::File,
                priority: ConfigPriority::EnvironmentFile,
                description: "异步重新加载所有来源".to_string(),
                changes: diff,
            };

            self.dynamic_updates.write().push(update);

            // 更新配置
            *self.config.write() = decrypted_new_config;

            info!("异步重新加载配置成功");
        } else {
            info!("未检测到配置更改");
        }

        Ok(())
    }
    /// 重新加载数据库配置
    pub fn reload_database_config(&mut self) -> ConfigResult<()> {
        info!("正在重新加载数据库配置");

        self.loader.reload_database_config()?;
        self.reload()?;

        Ok(())
    }
    /// 异步版本：重新加载数据库配置
    pub async fn reload_database_config_async(&mut self) -> ConfigResult<()> {
        info!("异步重载数据库配置");

        // 如果 loader 有异步的 reload 方法，使用它
        // 否则回退到同步版本
        if let Some(pool) = self.loader.get_db_pool().clone() {
            // 直接使用 DatabaseConfigLoader 重新加载
            if let Some(config_map) =
                DatabaseConfigLoader::load_config_from_db(&pool, &self.loader.get_env()).await?
            {
                // 应用数据库配置更新
                self.apply_database_updates(config_map).await?;
            }
        } else {
            self.reload_database_config()?;
        }

        Ok(())
    }
    /// 动态更新配置（最高优先级）
    pub fn update_config_dynamic(
        &self,
        updates: HashMap<String, serde_json::Value>,
    ) -> ConfigResult<()> {
        info!("动态更新配置");

        let old_config = self.config.read().clone();
        let old_value = serde_json::to_value(&old_config).map_err(|e| {
            ConfigError::SerializationFailed(format!("配置序列化失败: {}", e))
        })?;

        // 应用更新
        let mut new_value = old_value.clone();
        let updates_value = serde_json::to_value(updates).map_err(|e| {
            ConfigError::SerializationFailed(format!("更新序列化失败: {}", e))
        })?;

        ConfigMerger::deep_merge(&mut new_value, &updates_value, false);

        // 计算差异
        let diff = ConfigMerger::diff_configs(&old_value, &new_value);

        if diff.has_changes() {
            // 反序列化为AppConfig
            let new_config: AppConfig = serde_json::from_value(new_value).map_err(|e| {
                ConfigError::DeserializationFailed(format!(
                    "反序列化更新配置失败: {}",
                    e
                ))
            })?;

            // 验证新配置
            let validator = crate::validator::ConfigValidator::new();
            validator.validate(&new_config)?;

            // 记录动态更新
            let update = DynamicUpdate {
                timestamp: Utc::now(),
                source: ConfigSourceType::Runtime,
                priority: ConfigPriority::Runtime,
                description: "动态运行时更新".to_string(),
                changes: diff.clone(),
            };

            self.dynamic_updates.write().push(update);

            // 更新配置
            *self.config.write() = new_config;

            info!("配置已动态更新: {}", diff.summary());
        } else {
            info!("动态更新中没有配置更改");
        }

        Ok(())
    }
    /// 更新单个配置值
    pub fn update_config_value<T: serde::Serialize>(
        &self,
        path: &str,
        value: T,
    ) -> ConfigResult<()> {
        let value_json = serde_json::to_value(value).map_err(|e| {
            ConfigError::SerializationFailed(format!("{}值: 序列化失败", e))
        })?;

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
            return serde_json::from_value(value.clone()).map_err(|e| {
                ConfigError::ValueNotFound(format!(
                    "无法反序列化键的值 {}: {}",
                    key, e
                ))
            });
        }

        // TODO 这里可以实现从主配置中获取值的逻辑
        // 由于配置结构复杂，需要实现特定的解析逻辑

        Err(ConfigError::ValueNotFound(format!(
            "配置键未找到: {}",
            key
        )))
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

        let toml = toml::to_string_pretty(&encrypted_config).map_err(|e| {
            ConfigError::SerializationFailed(format!("配置序列化失败: {}", e))
        })?;

        std::fs::write(path, toml)
            .map_err(|e| ConfigError::IoError(format!("写入配置文件失败: {}", e)))?;

        info!("配置已加密导出到文件");
        Ok(())
    }

    /// 导入配置从文件（自动解密敏感配置）
    pub fn import_from_file<P: AsRef<Path>>(&self, path: P) -> ConfigResult<()> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(format!("读取配置文件失败: {}", e)))?;

        let new_config: AppConfig = toml::from_str(&content).map_err(|e| {
            ConfigError::DeserializationFailed(format!("配置反序列化失败: {}", e))
        })?;

        // 解密敏感配置
        let mut decrypted_config = new_config.clone();
        if let Some(encryptor) = &self.encryptor {
            encryptor.decrypt_config(&mut decrypted_config)?;
        }

        // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;

        *self.config.write() = decrypted_config;

        info!("已从文件导入并解密配置");
        Ok(())
    }

    /// 验证配置
    pub fn validate(&self) -> ConfigResult<()> {
        let config = self.config.read();
        config.validate().map_err(|e| {
            ConfigError::ValidationFailed(format!("配置验证失败: {}", e))
        })?;

        Ok(())
    }

    /// 获取配置源信息
    pub fn get_source_info(&self) -> Vec<ConfigSourceInfo> {
        self.loader.get_source_info()
    }
    /// 获取动态更新历史
    pub fn get_dynamic_update_history(&self, limit: usize) -> Vec<DynamicUpdate> {
        let updates = self.dynamic_updates.read();
        updates.iter().rev().take(limit).cloned().collect()
    }
    
    /// 启动密钥轮换监控
    pub async fn start_key_rotation_watching(
        &mut self,
        rotation_interval: Duration,
    ) -> ConfigResult<()> {
        if self.key_rotation_watcher.is_none() {
            let manager = Arc::new(RwLock::new(self.clone()));
            let key_watcher = KeyRotationWatcher::new(manager, rotation_interval);
            key_watcher.start()?;
            self.key_rotation_watcher = Some(key_watcher);
            info!("密钥轮换监控器已启动");
        }
        
        Ok(())
    }
    
    /// 停止密钥轮换监控
    pub fn stop_key_rotation_watching(&mut self) {
        if let Some(key_watcher) = &self.key_rotation_watcher {
            key_watcher.stop();
        }
        self.key_rotation_watcher = None;
    }
     /// 带数据库更新的密钥轮换
    pub async fn rotate_key_with_database_update(&mut self) -> ConfigResult<String> {
        info!("开始带数据库更新的密钥轮换...");
        
        // 1. 轮换密钥
        let new_key_id = self.rotate_key()?;
        
        // 2. 如果有数据库连接，重新加密数据库中的配置
        if let Some(pool) = &self.loader.get_db_pool() {
            info!("开始重新加密数据库配置...");
            
            match DatabaseConfigLoader::reencrypt_database_configs(pool).await {
                Ok(_) => {
                    info!("数据库配置重新加密成功");
                    
                    // 3. 重新加载数据库配置
                    self.reload_database_config_async().await?;
                    
                    // 4. 生成新的备份密钥
                    self.backup_encryption_key().await?;
                }
                Err(e) => {
                    error!("重新加密数据库配置失败: {}", e);
                    return Err(ConfigError::EncryptionError(format!(
                        "重新加密数据库配置失败: {}",
                        e
                    )));
                }
            }
        } else {
            warn!("未找到数据库连接池，跳过数据库配置重新加密");
        }
        
        // 5. 记录密钥轮换日志
        self.log_key_rotation(&new_key_id)?;
        
        info!("密钥轮换完成，新密钥ID: {}", new_key_id);
        Ok(new_key_id)
    }
    /// 重新加密数据库配置（供监控器调用）
    pub async fn reencrypt_database_configs(&self) -> ConfigResult<()> {
        if let Some(pool) = &self.loader.get_db_pool() {
            DatabaseConfigLoader::reencrypt_database_configs(pool).await
        } else {
            Err(ConfigError::DatabaseError(
                "数据库连接池未初始化".to_string(),
            ))
        }
    }
     /// 备份加密密钥
    async fn backup_encryption_key(&self) -> ConfigResult<()> {
        let encryptor = get_global_encryptor()?;
        let encryption_manager = encryptor.encryption_manager();
        let current_key = encryption_manager.get_base64_key();
        
        // 将密钥备份到安全的地方（例如：AWS Secrets Manager、HashiCorp Vault等）
        // 这里只是记录到日志，实际生产环境应该实现安全的密钥备份
        info!("新加密密钥已生成，请妥善备份");
        debug!("新密钥（base64）: {}", current_key);
        
        // TODO: 实现安全的密钥备份逻辑
        // self.backup_to_vault(&current_key).await?;
        
        Ok(())
    }
    
    /// 记录密钥轮换日志
    fn log_key_rotation(&self, key_id: &str) -> ConfigResult<()> {
        use chrono::Utc;
        
        let log_entry = format!(
            "[{}] 密钥轮换完成 - KeyID: {}",
            Utc::now().to_rfc3339(),
            key_id
        );
        
        // 记录到配置变更历史
        let mut dynamic_updates = self.dynamic_updates.write();
        dynamic_updates.push(DynamicUpdate {
            timestamp: Utc::now(),
            source: ConfigSourceType::Database,
            priority: ConfigPriority::Database,
            description: format!("密钥轮换: {}", key_id),
            changes: ConfigDiff {
                added: HashMap::new(),
                modified: HashMap::new(),
                removed: HashMap::new(),
            },
        });
        
        // 写入日志文件
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("logs/key_rotation.log")
            .map_err(|e| ConfigError::IoError(format!("打开日志文件失败: {}", e)))?;
        
        use std::io::Write;
        writeln!(&log_file, "{}", log_entry)
            .map_err(|e| ConfigError::IoError(format!("写入日志文件失败: {}", e)))?;
        
        Ok(())
    }
    
    /// 手动触发密钥轮换
    pub async fn manual_key_rotation(&mut self) -> ConfigResult<String> {
        info!("手动触发密钥轮换...");
        
        // 检查是否有数据库配置
        let has_database = self.loader.get_db_pool().is_some();
        
        if has_database {
            self.rotate_key_with_database_update().await
        } else {
            self.rotate_key()
        }
    }
    /// 启动配置监控
    pub fn start_watching(&mut self) -> ConfigResult<()> {
        if self.watcher.is_none() {
            let mut watcher =
                ConfigWatcher::new(self.config.clone(), PathBuf::from(DEFAULT_CONFIG_PATH))?;
            watcher.start()?;

            // 获取重载通道接收器
            self.reload_receiver = watcher.get_reload_receiver();

            self.watcher = Some(watcher);
            info!("配置监视器已启动");

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
                info!("从文件监视器接收到重新加载信号");
                // 使用异步重载
                match manager.reload_async().await {
                    Ok(_) => info!("配置重载成功"),
                    Err(e) => error!("重新加载配置失败: {}", e),
                }
            }
        });
        Ok(())
    }

    /// 停止配置监控
    pub fn stop_watching(&mut self) {
        if let Some(watcher) = &mut self.watcher {
            watcher.stop();
            info!("配置监视器停止运行");
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
            info!("数据库配置监视器启动");
        }

        Ok(())
    }
    /// 停止数据库配置监控
    pub fn stop_database_watching(&mut self) {
        if let Some(db_watcher) = &self.db_watcher {
            db_watcher.stop();
            info!("数据库配置监视器已停止");
        }
        self.db_watcher = None;
    }
    /// 启动自动重载任务
    pub async fn start_auto_reload_task(&self, check_interval: Duration) -> ConfigResult<()> {
        let manager = Arc::new(RwLock::new(self.clone()));
        ConfigWatcher::start_auto_reload(manager, check_interval).await
    }

    /// 检查配置是否需要重新加载
    pub fn should_reload(&self, interval_seconds: u64) -> bool {
        self.loader.should_reload(interval_seconds)
    }
    /// 检查配置是否需要重新加载
    pub async fn should_reload_from_db(&self, interval_seconds: u64) -> Result<bool, ConfigError> {
        self.loader.should_reload_from_db(interval_seconds).await  
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
                    Err(ConfigError::ValueNotFound(format!(
                        "未找到配置路径： {}",
                        path
                    )))
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
        let toml = toml::to_string_pretty(&*config).map_err(|e| {
            ConfigError::SerializationFailed(format!("配置序列化失败 {}", e))
        })?;

        Ok(toml)
    }

    /// 导入并合并配置
    pub fn import_and_merge_config(&self, toml_config: &str) -> ConfigResult<()> {
        let imported_config: AppConfig = toml::from_str(toml_config).map_err(|e| {
            ConfigError::DeserializationFailed(format!(
                "反序列化导入的配置失败: {}",
                e
            ))
        })?;

        let old_config = self.config.read().clone();

        // 合并配置
        let merged_config = old_config.clone();

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

        info!("配置已成功导入和合并");

        Ok(())
    }

    /// 应用数据库配置更新
    async fn apply_database_updates(
        &mut self,
        config_map: HashMap<String, String>,
    ) -> ConfigResult<()> {
        let mut updates = HashMap::new();

        for (key, value) in config_map {
            // 根据键确定如何更新配置
            match key.as_str() {
                "database.url" | "redis.password" | "jwt.secret" | "encryption.key" => {
                    updates.insert(key, serde_json::json!(value));
                }
                _ => {
                    // 尝试解析为 JSON，否则作为字符串处理
                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&value) {
                        updates.insert(key, json_value);
                    } else {
                        updates.insert(key, serde_json::json!(value));
                    }
                }
            };
        }

        if !updates.is_empty() {
            self.update_config_dynamic(updates.clone())?;
            info!("应用 {} 数据库配置更新", updates.len());
        }

        Ok(())
    }
    /// 启动密钥轮换任务（普通）
    async fn start_key_rotation_task(
        manager: Arc<ConfigManager>,
        rotation_interval: Duration,
    ) -> ConfigResult<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(rotation_interval);
            
            loop {
                interval.tick().await;
                
                match manager.rotate_key() {
                    Ok(new_key_id) => {
                        info!("密钥轮换完成，新密钥ID: {}", new_key_id);
                        
                        // 导出新密钥（供备份）
                        if let Ok(key) = Self::export_encryption_key() {
                            info!("新加密密钥已生成，请妥善保存");
                            debug!("新密钥（base64）: {}", key);
                        }
                    }
                    Err(e) => {
                        error!("密钥轮换失败: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    /// 14. 导出密钥
    pub fn export_encryption_key() -> ConfigResult<String> {
        info!("导出加密密钥");
        
        let encryptor = get_global_encryptor()?;
        let encryption_manager = encryptor.encryption_manager();
        let key = encryption_manager.get_base64_key();
        
        info!("加密密钥导出完成");
        Ok(key)
    }

}

