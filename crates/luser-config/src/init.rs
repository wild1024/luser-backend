
//! 配置初始化API - 提供各种配置初始化方式


use std::{collections::HashMap, path::Path, time::Duration};

use tracing::info;

use crate::{
    ConfigLoader, ConfigResult, DatabaseConfigLoader, config::AppConfig, constants::{DEFAULT_RUN_MODE, ENCRYPTION_KEY_ENV, RUN_MODE_ENV}, encryption::{ init_global_encryptor, init_global_encryptor_with_key_manager}, error::ConfigError, manager::ConfigManager
};

// 全局配置实例
lazy_static::lazy_static! {
    static ref GLOBAL_CONFIG: parking_lot::RwLock<Option<ConfigManager>> = parking_lot::RwLock::new(None);
}

// ==================== 配置初始化构建器 ====================

/// 配置初始化构建器
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    environment: Option<String>,
    enable_database: bool,
    enable_key_mgmt: bool,
    enable_hot_reload: bool,
    force_init: bool,
    encryption_key: Option<String>,
    key_rotation_interval: Option<Duration>,
    watch_intervals: WatchIntervals,
}

/// 监控间隔配置
#[derive(Debug, Clone)]
pub struct WatchIntervals {
    pub file_watch: Option<Duration>,
    pub db_watch: Option<Duration>,
    pub auto_reload: Option<Duration>,
}

impl Default for WatchIntervals {
    fn default() -> Self {
        Self {
            file_watch: Some(Duration::from_secs(5)),
            db_watch: Some(Duration::from_secs(60)),
            auto_reload: Some(Duration::from_secs(30)),
        }
    }
}

impl ConfigBuilder {
     /// 创建新的配置构建器
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置环境
    pub fn env(mut self, env: impl Into<String>) -> Self {
        self.environment = Some(env.into());
        self
    }

    /// 启用数据库配置
    pub fn with_db(mut self, enable: bool) -> Self {
        self.enable_database = enable;
        self
    }

    /// 启用密钥管理
    pub fn with_key_mgmt(mut self, enable: bool) -> Self {
        self.enable_key_mgmt = enable;
        self
    }

    /// 设置密钥轮换间隔
    pub fn key_rotation(mut self, interval: Duration) -> Self {
        self.key_rotation_interval = Some(interval);
        self
    }

    /// 启用热重载
    pub fn with_hot_reload(mut self, enable: bool) -> Self {
        self.enable_hot_reload = enable;
        self
    }

    /// 强制初始化数据库
    pub fn force_init(mut self, force: bool) -> Self {
        self.force_init = force;
        self
    }

    /// 设置加密密钥
    pub fn encryption_key(mut self, key: impl Into<String>) -> Self {
        self.encryption_key = Some(key.into());
        self
    }

    /// 设置监控间隔
    pub fn watch_intervals(mut self, intervals: WatchIntervals) -> Self {
        self.watch_intervals = intervals;
        self
    }

    /// 构建配置管理器
    pub async fn build(self) -> ConfigResult<ConfigManager> {
        self.build_manager().await
    }

    /// 构建并设置为全局配置
    pub async fn build_and_set(self) -> ConfigResult<()> {
        let manager = self.build_manager().await?;
        set_global_config(manager)?;
        Ok(())
    }

    /// 内部方法：构建配置管理器
    async fn build_manager(self) -> ConfigResult<ConfigManager> {
        let env = self.environment.clone()
            .unwrap_or_else(|| std::env::var(RUN_MODE_ENV)
                .unwrap_or_else(|_| DEFAULT_RUN_MODE.to_string()));
        
        // 1. 处理加密密钥
        self.setup_encryption()?;
        
        // 2. 构建配置管理器
        let mut manager = if self.enable_database {
            self.build_with_database(&env).await?
        } else {
            self.build_without_database(&env).await?
        };

        // 3. 启动监控
        if self.enable_hot_reload {
            self.start_monitoring(&manager).await?;
        }
        // 4. 启动秘钥轮转
        if self.enable_key_mgmt{
            let rotation_interval = self.key_rotation_interval
                .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60)); // 30天
            &manager.start_key_rotation_watching(rotation_interval).await?;
        }
        Ok(manager)
    }

    /// 设置加密
    fn setup_encryption(&self) -> ConfigResult<()> {
        // 检查环境变量中的加密密钥
        let env_key = std::env::var(ENCRYPTION_KEY_ENV).ok();
        let encryption_key = self.encryption_key.as_ref().or(env_key.as_ref());

        if self.enable_key_mgmt {
            let rotation_interval = self.key_rotation_interval
                .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60)); // 30天
            
            if let Some(key) = encryption_key {
                unsafe { std::env::set_var(ENCRYPTION_KEY_ENV, key) };
            }
            
            init_global_encryptor_with_key_manager(rotation_interval)?;
        } else {
            init_global_encryptor()?;
        }
        
        Ok(())
    }

    /// 构建无数据库配置的管理器
    async fn build_without_database(&self, env: &str) -> ConfigResult<ConfigManager> {
        info!("构建无数据库配置管理器，环境: {}", env);
        
        if self.enable_key_mgmt {
            let rotation_interval = self.key_rotation_interval
                .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60));
            
            ConfigManager::with_env_and_key_management(
                env,
                Some(rotation_interval),
            )
        } else {
            ConfigManager::with_environment(env)
        }
    }

    /// 构建带数据库配置的管理器
    async fn build_with_database(&self, env: &str) -> ConfigResult<ConfigManager> {
        info!("构建带数据库配置管理器，环境: {}", env);
        
        // 1. 首先加载本地配置，获取数据库连接信息
        let mut loader = ConfigLoader::new();
        loader.set_environment(env);
        
        let local_config = loader.load()?;
        let db_loader = DatabaseConfigLoader;
        // 2. 创建数据库连接池
        let db_pool = db_loader.create_db_pool(&local_config).await?;
        
        // 3. 检查数据库配置状态
        let has_db_config = db_loader.has_database_config(&db_pool, env).await?;
        
        // 4. 根据是否强制初始化处理数据库配置
        if self.force_init {
            info!("强制初始化：同步本地配置到数据库");
            
            // 强制初始化：先同步本地配置到数据库
            db_loader.sync_local_config_to_database(&db_pool, env, &local_config).await?;
            
            // 重新加载配置，包含数据库配置源 
            // 创建配置管理器
            let mut manager = ConfigManager::with_database(env, db_pool)?;
            
            // 如果启用了密钥管理，设置密钥管理
            if self.enable_key_mgmt {
                let rotation_interval = self.key_rotation_interval
                    .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60));
                manager.enable_key_management(rotation_interval)?;
            }
            
            info!("强制初始化完成，以本地配置为准");
            Ok(manager)
        } else {
            // 非强制初始化：优先使用数据库配置
            if has_db_config {
                info!("数据库已有配置，使用数据库配置");

                // 创建配置管理器
                let mut manager = ConfigManager::with_database(env, db_pool)?;
                
                // 如果启用了密钥管理，设置密钥管理
                if self.enable_key_mgmt {
                    let rotation_interval = self.key_rotation_interval
                        .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60));
                    manager.enable_key_management(rotation_interval)?;
                }
                
                info!("使用数据库配置完成");
                Ok(manager)
            } else {
                info!("数据库无配置，使用本地配置");
                
                // 数据库无配置，使用本地配置
                let mut manager = ConfigManager::with_environment(env)?;
                
                // 如果启用了密钥管理，设置密钥管理
                if self.enable_key_mgmt {
                    let rotation_interval = self.key_rotation_interval
                        .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60));
                    manager.enable_key_management(rotation_interval)?;
                }
                
                info!("使用本地配置完成");
                Ok(manager)
            }
        }
    }

    /// 启动监控
    async fn start_monitoring(&self, manager: &ConfigManager) -> ConfigResult<()> {
        let mut manager_clone = manager.clone();
        
        // 启动文件监控
        if let Some(interval) = self.watch_intervals.file_watch {
            manager_clone.start_watching()?;
        }
        
        // 启动数据库监控
        if let Some(interval) = self.watch_intervals.db_watch {
            manager_clone.start_database_watching(interval).await?;
        }
        
        // 启动自动重载任务
        if let Some(interval) = self.watch_intervals.auto_reload {
            manager_clone.start_auto_reload_task(interval).await?;
        }
        
        Ok(())
    }

}
// ==================== 基础初始化方法(含自动获取环境变量秘钥加密解密配置) ====================

/// 1. 初始化基础版全局配置
pub async fn init_config() -> ConfigResult<()> {
    info!("初始化基础版全局配置...");
    
    ConfigBuilder::new()
        .build_and_set()
        .await
}
/// 2. 初始化全局配置（指定环境）
pub async fn init_config_with_env(env: impl Into<String>) -> ConfigResult<()> {
     let env_string = env.into();
    info!("初始化全局配置（指定环境: {}）...", env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .build_and_set()
        .await
}
/// 3. 初始化全局配置（含密钥管理）
pub async fn init_config_with_key_mgmt() -> ConfigResult<()> {
    info!("初始化全局配置（含密钥管理）...");
    
    ConfigBuilder::new()
        .with_key_mgmt(true)
        .build_and_set()
        .await
}

/// 4. 初始化全局配置（指定环境，含密钥管理）
pub async fn init_config_with_env_and_key_mgmt(env: impl Into<String>) -> ConfigResult<()> {
     let env_string = env.into();
    info!("初始化全局配置（指定环境: {}, 含密钥管理）...", env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .with_key_mgmt(true)
        .build_and_set()
        .await
}

/// 5. 初始化全局配置（含密钥管理+热重载）
pub async fn init_config_with_full() -> ConfigResult<()> {
    info!("初始化全局配置（含密钥管理+热重载）...");
    
    ConfigBuilder::new()
        .with_key_mgmt(true)
        .with_hot_reload(true)
        .build_and_set()
        .await
}

/// 6. 初始化全局配置（指定环境，含密钥管理+热重载）
pub async fn init_config_with_env_full(env: impl Into<String>) -> ConfigResult<()> {
     let env_string = env.into();
    info!("初始化全局配置（指定环境: {}, 含密钥管理+热重载）...", env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .with_key_mgmt(true)
        .with_hot_reload(true)
        .build_and_set()
        .await
}
// ==================== 数据库配置初始化方法 ====================

/// 1. 初始化全局配置（含数据库配置）
pub async fn init_config_with_db() -> ConfigResult<()> {
    info!("初始化全局配置（含数据库配置）...");
    
    ConfigBuilder::new()
        .with_db(true)
        .build_and_set()
        .await
}

/// 2. 初始化全局配置（指定环境，数据库配置）
pub async fn init_config_with_env_and_db(env: impl Into<String>) -> ConfigResult<()> {
     let env_string = env.into();
    info!("初始化全局配置（指定环境: {}, 数据库配置）...", env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .with_db(true)
        .build_and_set()
        .await
}

/// 3. 初始化全局配置（含密钥管理，数据库配置）
pub async fn init_config_with_key_mgmt_and_db() -> ConfigResult<()> {
    info!("初始化全局配置（含密钥管理，数据库配置）...");
    
    ConfigBuilder::new()
        .with_db(true)
        .with_key_mgmt(true)
        .build_and_set()
        .await
}

/// 4. 初始化全局配置（指定环境，含密钥管理，数据库配置）
pub async fn init_config_with_env_key_mgmt_and_db(
    env: impl Into<String>,
) -> ConfigResult<()> {
     let env_string = env.into();
    info!("初始化全局配置（指定环境: {}, 含密钥管理，数据库配置）...", env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .with_db(true)
        .with_key_mgmt(true)
        .build_and_set()
        .await
}

/// 5. 初始化全局配置（含密钥管理+热重载，数据库配置）
pub async fn init_config_with_db_full() -> ConfigResult<()> {
    info!("初始化全局配置（含密钥管理+热重载，数据库配置）...");
    
    ConfigBuilder::new()
        .with_db(true)
        .with_key_mgmt(true)
        .with_hot_reload(true)
        .build_and_set()
        .await
}

/// 6. 初始化全局配置（指定环境，含密钥管理+热重载，数据库配置）
pub async fn init_config_with_env_db_full(
    env: impl Into<String>,
) -> ConfigResult<()> {
     let env_string = env.into();
    info!("初始化全局配置（指定环境: {}, 含密钥管理+热重载，数据库配置）...", env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .with_db(true)
        .with_key_mgmt(true)
        .with_hot_reload(true)
        .build_and_set()
        .await
}

// ==================== 强制初始化数据库方法 ====================

/// 1. 初始化全局配置（含数据库配置）-强制
pub async fn init_config_with_db_force() -> ConfigResult<()> {
    info!("强制初始化全局配置（含数据库配置）...");
    
    ConfigBuilder::new()
        .with_db(true)
        .force_init(true)
        .build_and_set()
        .await
}

/// 2. 初始化全局配置（指定环境，数据库配置）-强制
pub async fn init_config_with_env_and_db_force(env: impl Into<String>) -> ConfigResult<()> {
     let env_string = env.into();
    info!("强制初始化全局配置（指定环境: {}, 数据库配置）...",env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .with_db(true)
        .force_init(true)
        .build_and_set()
        .await
}

/// 3. 初始化全局配置（含密钥管理，数据库配置）-强制
pub async fn init_config_with_key_mgmt_and_db_force() -> ConfigResult<()> {
    info!("强制初始化全局配置（含密钥管理，数据库配置）...");
    
    ConfigBuilder::new()
        .with_db(true)
        .with_key_mgmt(true)
        .force_init(true)
        .build_and_set()
        .await
}

/// 4. 初始化全局配置（指定环境，含密钥管理，数据库配置）-强制
pub async fn init_config_with_env_key_mgmt_and_db_force(
    env: impl Into<String>,
) -> ConfigResult<()> {
     let env_string = env.into();
    info!("强制初始化全局配置（指定环境: {}, 含密钥管理，数据库配置）...", env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .with_db(true)
        .with_key_mgmt(true)
        .force_init(true)
        .build_and_set()
        .await
}

/// 5. 初始化全局配置（含密钥管理+热重载，数据库配置）-强制
pub async fn init_config_with_db_force_full() -> ConfigResult<()> {
    info!("强制初始化全局配置（含密钥管理+热重载，数据库配置）...");
    
    ConfigBuilder::new()
        .with_db(true)
        .with_key_mgmt(true)
        .with_hot_reload(true)
        .force_init(true)
        .build_and_set()
        .await
}

/// 6. 初始化全局配置（指定环境，含密钥管理+热重载，数据库配置）-强制
pub async fn init_config_with_env_db_force_full(
    env: impl Into<String>,
) -> ConfigResult<()> {
     let env_string = env.into();
    info!("强制初始化全局配置（指定环境: {}, 含密钥管理+热重载，数据库配置）...", env_string);
    
    ConfigBuilder::new()
        .env(env_string)
        .with_db(true)
        .with_key_mgmt(true)
        .with_hot_reload(true)
        .force_init(true)
        .build_and_set()
        .await
}

// ==================== 全局配置管理 ====================

/// 设置全局配置
pub fn set_global_config(manager: ConfigManager) -> ConfigResult<()> {
    let mut global_config = GLOBAL_CONFIG.write();
    *global_config = Some(manager);
    Ok(())
}

/// 获取全局配置管理器
pub fn get_global_config() -> ConfigResult<ConfigManager> {
    let global_config = GLOBAL_CONFIG.read();
    global_config
        .as_ref()
        .cloned()
        .ok_or_else(|| ConfigError::NotInitialized("全局配置未初始化".to_string()))
}

/// 获取全局配置实例
pub fn get_config() -> ConfigResult<AppConfig> {
    get_global_config().map(|manager| manager.get_config())
}

/// 重新加载全局配置
pub fn reload_config() -> ConfigResult<()> {
    let mut global_config = GLOBAL_CONFIG.write();
    if let Some(config) = global_config.as_mut() {
        config.reload()
    } else {
        Err(ConfigError::NotInitialized("全局配置未初始化".to_string()))
    }
}

/// 异步重新加载全局配置
pub async fn reload_async() -> ConfigResult<()> {
    let mut global_config = GLOBAL_CONFIG.write();
    if let Some(config) = global_config.as_mut() {
        config.reload_async().await
    } else {
        Err(ConfigError::NotInitialized("全局配置未初始化".to_string()))
    }
}

/// 便捷方法：获取配置值
pub fn get<T: serde::de::DeserializeOwned>(key: &str) -> ConfigResult<T> {
    get_global_config()?.get_value(key)
}

/// 便捷方法：设置配置值
pub fn set<T: serde::Serialize>(key: &str, value: T) -> ConfigResult<()> {
    get_global_config()?.set_value(key, value)
}