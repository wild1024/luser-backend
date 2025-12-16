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

/// 错误处理工具
pub struct ErrorHandler;

impl ErrorHandler {
    /// 处理配置错误
    pub fn handle_error(err: &ConfigError) -> String {
        match err {
            ConfigError::LoadFailed(msg) => {
                format!("配置加载失败: {}", msg)
            }
            ConfigError::DeserializationFailed(msg) => {
                format!("配置解析失败: {}", msg)
            }
            ConfigError::ValidationFailed(msg) => {
                format!("配置验证失败: {}", msg)
            }
            ConfigError::ValueNotFound(key) => {
                format!("配置项未找到: {}", key)
            }
            ConfigError::NotInitialized(msg) => {
                format!("配置未初始化: {}", msg)
            }
            ConfigError::EncryptionError(msg) => {
                format!("配置加密错误: {}", msg)
            }
             ConfigError::DatabaseError(msg) => {
                format!("数据库错误: {}", msg)
            }
            ConfigError::IoError(msg) => {
                format!("配置IO错误: {}", msg)
            }
            ConfigError::EnvError(msg) => {
                format!("环境变量错误: {}", msg)
            }
            _ => {
                format!("配置错误: {}", err)
            }
        }
    }
    
    /// 将错误转换为用户友好的消息
    pub fn to_user_friendly(err: &ConfigError) -> String {
        match err {
            ConfigError::LoadFailed(_) => {
                "无法加载配置文件，请检查文件是否存在且格式正确".to_string()
            }
            ConfigError::ValidationFailed(_) => {
                "配置验证失败，请检查配置项是否正确".to_string()
            }
            ConfigError::NotInitialized(_) => {
                "配置未初始化，请先初始化配置".to_string()
            }
            ConfigError::ValueNotFound(key) => {
                format!("配置项 '{}' 未找到，请检查配置", key)
            }
            ConfigError::DatabaseError(key) => {
                format!("数据库错误： '{}'", key)
            }
            _ => {
                "配置处理过程中发生错误".to_string()
            }
        }
    }
    
    /// 检查错误是否可恢复
    pub fn is_recoverable(err: &ConfigError) -> bool {
        match err {
            ConfigError::NotInitialized(_) => true,
            ConfigError::ValueNotFound(_) => true,
            ConfigError::EnvError(_) => true,
            _ => false,
        }
    }
    
    /// 创建错误上下文
    pub fn with_context(err: ConfigError, context: &str) -> ConfigError {
        match err {
            ConfigError::LoadFailed(msg) => {
                ConfigError::LoadFailed(format!("{}: {}", context, msg))
            }
            ConfigError::DeserializationFailed(msg) => {
                ConfigError::DeserializationFailed(format!("{}: {}", context, msg))
            }
            ConfigError::ValidationFailed(msg) => {
                ConfigError::ValidationFailed(format!("{}: {}", context, msg))
            }
            ConfigError::ValueNotFound(key) => {
                ConfigError::ValueNotFound(format!("{}: {}", context, key))
            }
            ConfigError::NotInitialized(msg) => {
                ConfigError::NotInitialized(format!("{}: {}", context, msg))
            }
            ConfigError::EncryptionError(msg) => {
                ConfigError::EncryptionError(format!("{}: {}", context, msg))
            }
            ConfigError::IoError(msg) => {
                ConfigError::IoError(format!("{}: {}", context, msg))
            }
            ConfigError::EnvError(msg) => {
                ConfigError::EnvError(format!("{}: {}", context, msg))
            }
            ConfigError::UnsupportedFormat(msg) => {
                ConfigError::UnsupportedFormat(format!("{}: {}", context, msg))
            }
            ConfigError::WatchError(msg) => {
                ConfigError::WatchError(format!("{}: {}", context, msg))
            }
            ConfigError::CacheError(msg) => {
                ConfigError::CacheError(format!("{}: {}", context, msg))
            }
            ConfigError::Unknown(msg) => {
                ConfigError::Unknown(format!("{}: {}", context, msg))
            }
            ConfigError::DecryptionError(msg) => {
                ConfigError::DecryptionError(format!("{}: {}", context, msg))
            }
            ConfigError::SerializationFailed(msg) => {
                ConfigError::SerializationFailed(format!("{}: {}", context, msg))
            }
            ConfigError::DatabaseError(msg) => {
                ConfigError::DatabaseError(format!("{}: {}", context, msg))
            },
        }
    }
}

/// 错误代码
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// 配置加载错误
    LoadError = 1001,
    /// 配置解析错误
    ParseError = 1002,
    /// 配置验证错误
    ValidationError = 1003,
    /// 配置未找到错误
    NotFoundError = 1004,
    /// 配置未初始化错误
    NotInitializedError = 1005,
    /// 加密错误
    EncryptionError = 1006,
    /// IO错误
    IoError = 1007,
    /// 环境变量错误
    EnvError = 1008,
    /// 配置未找到错误
    DatabaseError = 1009,
    /// 未知错误
    UnknownError = 1999,
}

impl From<&ConfigError> for ErrorCode {
    fn from(err: &ConfigError) -> Self {
        match err {
            ConfigError::LoadFailed(_) => ErrorCode::LoadError,
            ConfigError::DeserializationFailed(_) => ErrorCode::ParseError,
            ConfigError::SerializationFailed(_) => ErrorCode::ParseError,
            ConfigError::ValidationFailed(_) => ErrorCode::ValidationError,
            ConfigError::ValueNotFound(_) => ErrorCode::NotFoundError,
            ConfigError::DatabaseError(_) => ErrorCode::DatabaseError,
            ConfigError::NotInitialized(_) => ErrorCode::NotInitializedError,
            ConfigError::EncryptionError(_) => ErrorCode::EncryptionError,
            ConfigError::DecryptionError(_) => ErrorCode::EncryptionError,
            ConfigError::IoError(_) => ErrorCode::IoError,
            ConfigError::EnvError(_) => ErrorCode::EnvError,
            _ => ErrorCode::UnknownError,
        }
    }
}

impl ErrorCode {
    /// 获取错误代码描述
    pub fn description(&self) -> &'static str {
        match self {
            ErrorCode::LoadError => "配置加载失败",
            ErrorCode::ParseError => "配置解析失败",
            ErrorCode::ValidationError => "配置验证失败",
            ErrorCode::NotFoundError => "配置项未找到",
            ErrorCode::DatabaseError => "数据库加载错误",
            ErrorCode::NotInitializedError => "配置未初始化",
            ErrorCode::EncryptionError => "配置加密/解密失败",
            ErrorCode::IoError => "配置IO操作失败",
            ErrorCode::EnvError => "环境变量操作失败",
            ErrorCode::UnknownError => "未知配置错误",
        }
    }
    
    /// 获取HTTP状态码
    pub fn http_status_code(&self) -> u16 {
        match self {
            ErrorCode::LoadError => 500,
            ErrorCode::ParseError => 400,
            ErrorCode::ValidationError => 400,
            ErrorCode::NotFoundError => 404,
            ErrorCode::NotInitializedError => 503,
            ErrorCode::EncryptionError => 500,
            ErrorCode::IoError => 500,
            ErrorCode::EnvError => 500,
            ErrorCode::UnknownError => 500,
            ErrorCode::DatabaseError => 500,
        }
    }
}