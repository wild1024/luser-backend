use thiserror::Error;
use std::io;

/// 配置错误类型
#[derive(Error, Debug)]
pub enum ConfigError {
    /// 配置加载失败
    #[error("加载配置失败: {0}")]
    LoadFailed(String),
    
    /// 配置反序列化失败
    #[error("配置反序列化失败: {0}")]
    DeserializationFailed(String),
    
    /// 配置序列化失败
    #[error("配置序列化失败: {0}")]
    SerializationFailed(String),
    
    /// 配置验证失败
    #[error("配置验证失败: {0}")]
    ValidationFailed(String),
    
    /// 数据库错误
    #[error("数据库错误: {0}")]
    DatabaseError(String),

    /// 配置值未找到
    #[error("未找到配置值: {0}")]
    ValueNotFound(String),
    
    /// 配置未初始化
    #[error("配置未初始化: {0}")]
    NotInitialized(String),
    
    /// 加密错误
    #[error("加密错误: {0}")]
    EncryptionError(String),
    
    /// 解密错误
    #[error("解密错误: {0}")]
    DecryptionError(String),
    
    /// 文件I/O错误
    #[error("I/O 错误: {0}")]
    IoError(String),
    
    /// 环境变量错误
    #[error("环境变量错误: {0}")]
    EnvError(String),
    
    /// 不支持的配置格式
    #[error("不支持的配置格式: {0}")]
    UnsupportedFormat(String),
    
    /// 配置文件监控错误
    #[error("配置文件监视错误: {0}")]
    WatchError(String),
    
    /// 配置缓存错误
    #[error("配置缓存错误: {0}")]
    CacheError(String),
    
    /// 未知错误
    #[error("未知配置错误: {0}")]
    Unknown(String),
}

/// 配置结果类型
pub type ConfigResult<T> = Result<T, ConfigError>;

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> Self {
        ConfigError::IoError(err.to_string())
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        ConfigError::DeserializationFailed(err.to_string())
    }
}

impl From<toml::ser::Error> for ConfigError {
    fn from(err: toml::ser::Error) -> Self {
        ConfigError::SerializationFailed(err.to_string())
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> Self {
        ConfigError::SerializationFailed(err.to_string())
    }
}

impl From<config::ConfigError> for ConfigError {
    fn from(err: config::ConfigError) -> Self {
        ConfigError::LoadFailed(err.to_string())
    }
}

impl From<validator::ValidationErrors> for ConfigError {
    fn from(err: validator::ValidationErrors) -> Self {
        ConfigError::ValidationFailed(err.to_string())
    }
}

impl From<aes_gcm::Error> for ConfigError {
    fn from(err: aes_gcm::Error) -> Self {
        ConfigError::EncryptionError(err.to_string())
    }
}

impl From<ring::error::Unspecified> for ConfigError {
    fn from(err: ring::error::Unspecified) -> Self {
        ConfigError::EncryptionError(err.to_string())
    }
}

impl From<base64::DecodeError> for ConfigError {
    fn from(err: base64::DecodeError) -> Self {
        ConfigError::EncryptionError(err.to_string())
    }
}

impl From<hex::FromHexError> for ConfigError {
    fn from(err: hex::FromHexError) -> Self {
        ConfigError::EncryptionError(err.to_string())
    }
}
