use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn, instrument};
use config::{Config, File, Environment, FileFormat};
use validator::Validate;
use crate::{AppConfig, ConfigError, ConfigResult, ConfigSecurityLevel, DEFAULT_CONFIG_PATH, ENV_PREFIX, get_global_encryptor, init_global_encryptor};

/// 配置加载器
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    sources: Vec<ConfigSource>,
    environment: String,
    config_dir: PathBuf,
}

/// 配置源
#[derive(Debug, Clone)]
pub enum ConfigSource {
    /// 文件源
    File {
        path: PathBuf,
        required: bool,
        format: FileFormat,
    },
    /// 环境变量源
    Environment {
        prefix: String,
        separator: String,
    },
    /// 默认值
    Defaults,
}

impl ConfigLoader {
    /// 创建新的配置加载器
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            environment: std::env::var("RUN_MODE")
                .unwrap_or_else(|_| "development".to_string()),
            config_dir: PathBuf::from(DEFAULT_CONFIG_PATH),
        }
    }
    
    /// 设置环境
    pub fn set_environment(&mut self, env: &str) -> &mut Self {
        self.environment = env.to_string();
        self
    }
    
    /// 设置配置目录
    pub fn set_config_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.config_dir = dir.as_ref().to_path_buf();
        self
    }
    
    /// 添加配置文件源
    pub fn add_source_file<P: AsRef<Path>>(&mut self, path: P) -> ConfigResult<&mut Self> {
        self.sources.push(ConfigSource::File {
            path: path.as_ref().to_path_buf(),
            required: true,
            format: FileFormat::Toml,
        });
        Ok(self)
    }
    
    /// 添加可选配置文件源
    pub fn add_optional_source_file<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.sources.push(ConfigSource::File {
            path: path.as_ref().to_path_buf(),
            required: false,
            format: FileFormat::Toml,
        });
        self
    }
    
    /// 添加环境变量源
    pub fn add_environment_source(&mut self, prefix: &str, separator: &str) -> &mut Self {
        self.sources.push(ConfigSource::Environment {
            prefix: prefix.to_string(),
            separator: separator.to_string(),
        });
        self
    }
    
    /// 添加默认值源
    pub fn add_defaults_source(&mut self) -> &mut Self {
        self.sources.push(ConfigSource::Defaults);
        self
    }
    
    /// 加载配置
    #[instrument(skip(self), name = "config.load")]
    pub fn load(&mut self) -> ConfigResult<AppConfig> {
        info!("Loading configuration for environment: {}", self.environment);
        
        let mut config_builder = Config::builder();
        
        // 添加默认配置目录
        self.add_default_sources();
        
        // 处理所有配置源
        for source in &self.sources {
            match source {
                ConfigSource::File { path, required, format } => {
                    self.add_file_source(&mut config_builder, path, *required, *format)?;
                }
                ConfigSource::Environment { prefix, separator } => {
                    self.add_env_source(&mut config_builder, prefix, separator);
                }
                ConfigSource::Defaults => {
                    // 默认值已经在AppConfig中定义
                }
            }
        }
        
        // 构建并反序列化配置
        let config = config_builder.build()
            .map_err(|e| ConfigError::LoadFailed(format!("Failed to build config: {}", e)))?;
        
        let app_config: AppConfig = config.try_deserialize()
            .map_err(|e| ConfigError::DeserializationFailed(format!("Failed to deserialize config: {}", e)))?;
        
        info!("Configuration loaded successfully");
        Ok(app_config)
    }
    
    /// 从环境变量加载配置
    pub fn load_from_env(&mut self) -> ConfigResult<AppConfig> {
        info!("Loading configuration from environment variables");
        
        let config = Config::builder()
            .add_source(Environment::with_prefix(ENV_PREFIX).separator("_"))
            .build()
            .map_err(|e| ConfigError::LoadFailed(format!("Failed to build config from env: {}", e)))?;
        
        let app_config: AppConfig = config.try_deserialize()
            .map_err(|e| ConfigError::DeserializationFailed(format!("Failed to deserialize config from env: {}", e)))?;
        
        info!("Configuration loaded from environment variables successfully");
        Ok(app_config)
    }
    
    /// 从文件加载配置
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> ConfigResult<AppConfig> {
        info!("Loading configuration from file: {:?}", path.as_ref());
        
        let config = Config::builder()
            .add_source(File::from(path.as_ref()))
            .build()
            .map_err(|e| ConfigError::LoadFailed(format!("Failed to build config from file: {}", e)))?;
        
        let app_config: AppConfig = config.try_deserialize()
            .map_err(|e| ConfigError::DeserializationFailed(format!("Failed to deserialize config from file: {}", e)))?;
        
        info!("Configuration loaded from file successfully");
        Ok(app_config)
    }
    
    /// 添加默认配置源
    fn add_default_sources(&mut self) {
        // 添加默认配置文件
        let default_config = self.config_dir.join("default.toml");
        if default_config.exists() {
            self.sources.push(ConfigSource::File {
                path: default_config,
                required: false,
                format: FileFormat::Toml,
            });
        }
        
        // 添加环境特定配置文件
        let env_config = self.config_dir.join(format!("{}.toml", self.environment));
        if env_config.exists() {
            self.sources.push(ConfigSource::File {
                path: env_config,
                required: false,
                format: FileFormat::Toml,
            });
        }
        
        // 添加环境变量源
        self.sources.push(ConfigSource::Environment {
            prefix: ENV_PREFIX.to_string(),
            separator: "_".to_string(),
        });
    }
    
    /// 添加文件源
    fn add_file_source(
        &self,
        builder: &mut config::ConfigBuilder<config::builder::DefaultState>,
        path: &Path,
        required: bool,
        format: FileFormat,
    ) -> ConfigResult<()> {
        if path.exists() {
            info!("Adding config file: {:?}", path);
            builder.add_source(File::from(path).format(format));
        } else if required {
            return Err(ConfigError::LoadFailed(format!("Required config file not found: {:?}", path)));
        } else {
            warn!("Optional config file not found: {:?}", path);
        }
        Ok(())
    }
    
    /// 添加环境变量源
    fn add_env_source(
        &self,
        builder: &mut config::ConfigBuilder<config::builder::DefaultState>,
        prefix: &str,
        separator: &str,
    ) {
        info!("Adding environment variable source with prefix: {}", prefix);
        builder.add_source(Environment::with_prefix(prefix).separator(separator));
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// 配置管理器
#[derive(Debug, Clone)]
pub struct ConfigManager {
    config: Arc<RwLock<AppConfig>>,
    loader: ConfigLoader,
}

impl ConfigManager {
    /// 创建新的配置管理器（自动解密敏感配置）
    pub fn new() -> ConfigResult<Self> {
        let mut loader = ConfigLoader::new();
        let config = loader.load()?;
          // 初始化全局加密器
        init_global_encryptor()?;
         // 解密敏感配置
        let mut decrypted_config = config.clone();
        let encryptor = get_global_encryptor()?;
        encryptor.decrypt_config(&mut decrypted_config)?;

         // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;

       Ok(Self {
            config: Arc::new(RwLock::new(decrypted_config)),
            loader,
        })
    }
    
     /// 从指定环境创建配置管理器（自动解密敏感配置）
    pub fn with_environment(env: &str) -> ConfigResult<Self> {
       let mut loader = ConfigLoader::new();
        loader.set_environment(env);
        let config = loader.load()?;
        
        // 初始化全局加密器
        init_global_encryptor()?;
        
        // 解密敏感配置
        let mut decrypted_config = config.clone();
        let encryptor = get_global_encryptor()?;
        encryptor.decrypt_config(&mut decrypted_config)?;
        
        // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;
        
        Ok(Self {
            config: Arc::new(RwLock::new(decrypted_config)),
            loader,
        })
    }
    
    /// 获取当前配置
    pub fn get_config(&self) -> AppConfig {
        self.config.read().clone()
    }
    
    /// 获取配置引用
    pub fn get_config_ref(&self) -> std::sync::RwLockReadGuard<'_, AppConfig> {
        self.config.read()
    }
    
    /// 重新加载配置（自动解密敏感配置）
    pub fn reload(&mut self) -> ConfigResult<()> {
       info!("Reloading configuration");
        
        let new_config = self.loader.load()?;
        
        // 解密敏感配置
        let mut decrypted_config = new_config.clone();
        let encryptor = get_global_encryptor()?;
        encryptor.decrypt_config(&mut decrypted_config)?;
        
        // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;
        
        *self.config.write() = decrypted_config;
        
        info!("Configuration reloaded successfully");
        Ok(())
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
        
        // 这里可以实现从主配置中获取值的逻辑
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
        let encryptor = get_global_encryptor()?;
        encryptor.encrypt_config(&mut encrypted_config)?;
        
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
        let encryptor = get_global_encryptor()?;
        encryptor.decrypt_config(&mut decrypted_config)?;
        
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
    
    /// 获取环境信息
    pub fn environment(&self) -> String {
        self.loader.environment.clone()
    }
    
    /// 检查配置是否已加载
    pub fn is_loaded(&self) -> bool {
        !self.config.read().server.host.is_empty()
    }
    /// 获取配置值的加密版本
    pub fn get_encrypted_value(&self, key: &str) -> ConfigResult<String> {
        let config = self.config.read();
        
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
    get_global_config()?.get_config()
}

/// 便捷函数：获取配置值
pub fn get_config<T: serde::de::DeserializeOwned>(key: &str) -> ConfigResult<T> {
    get_global_config()?.get_value(key)
}

/// 便捷函数：设置配置值
pub fn set_config<T: serde::Serialize>(key: &str, value: T) -> ConfigResult<()> {
    get_global_config()?.set_value(key, value)
}