
use thiserror::Error;
use serde::{Deserialize, Serialize};

/// Luser平台通用错误类型
#[derive(Error, Debug, Serialize, Deserialize, Clone)]
pub enum LuserError {
    /// 业务逻辑错误
    #[error("业务错误: {0}")]
    BusinessError(String),
    
    /// 认证失败
    #[error("认证失败: {0}")]
    AuthenticationError(String),
    
    /// 授权失败
    #[error("授权失败: {0}")]
    AuthorizationError(String),
    
    /// 参数验证失败
    #[error("参数验证失败: {0}")]
    ValidationError(String),
    
    /// 数据库错误
    #[error("数据库错误: {0}")]
    DatabaseError(String),
    
    /// 云服务错误
    #[error("云服务错误: {0}")]
    CloudServiceError(String),
    
    /// 支付服务错误
    #[error("支付服务错误: {0}")]
    PaymentServiceError(String),
    
    /// 网络错误
    #[error("网络错误: {0}")]
    NetworkError(String),
    
    /// 文件操作错误
    #[error("文件操作错误: {0}")]
    FileError(String),
    
    /// 配置错误
    #[error("配置错误: {0}")]
    ConfigError(String),
    
    /// 数据不存在
    #[error("数据不存在: {0}")]
    NotFoundError(String),
    
    /// 数据已存在
    #[error("数据已存在: {0}")]
    AlreadyExistsError(String),
    
    /// 请求频率限制
    #[error("请求过于频繁，请稍后再试")]
    RateLimitError,
    
    /// 服务暂时不可用
    #[error("服务暂时不可用，请稍后重试")]
    ServiceUnavailable,
    
    /// 未知错误
    #[error("未知错误: {0}")]
    UnknownError(String),
}

/// 通用结果类型
pub type LuserResult<T> = Result<T, LuserError>;

impl LuserError {
    /// 获取HTTP状态码
    pub fn http_status_code(&self) -> u16 {
        match self {
            LuserError::BusinessError(_) => 400,
            LuserError::AuthenticationError(_) => 401,
            LuserError::AuthorizationError(_) => 403,
            LuserError::ValidationError(_) => 422,
            LuserError::DatabaseError(_) => 500,
            LuserError::CloudServiceError(_) => 502,
            LuserError::PaymentServiceError(_) => 502,
            LuserError::NetworkError(_) => 503,
            LuserError::FileError(_) => 500,
            LuserError::ConfigError(_) => 500,
            LuserError::NotFoundError(_) => 404,
            LuserError::AlreadyExistsError(_) => 409,
            LuserError::RateLimitError => 429,
            LuserError::ServiceUnavailable => 503,
            LuserError::UnknownError(_) => 500,
        }
    }
    
    /// 转换为API错误
    pub fn to_api_error(&self) -> crate::ApiError {
        let code = match self {
            LuserError::BusinessError(_) => "BUSINESS_ERROR",
            LuserError::AuthenticationError(_) => "AUTHENTICATION_ERROR",
            LuserError::AuthorizationError(_) => "AUTHORIZATION_ERROR",
            LuserError::ValidationError(_) => "VALIDATION_ERROR",
            LuserError::DatabaseError(_) => "DATABASE_ERROR",
            LuserError::CloudServiceError(_) => "CLOUD_SERVICE_ERROR",
            LuserError::PaymentServiceError(_) => "PAYMENT_SERVICE_ERROR",
            LuserError::NetworkError(_) => "NETWORK_ERROR",
            LuserError::FileError(_) => "FILE_ERROR",
            LuserError::ConfigError(_) => "CONFIG_ERROR",
            LuserError::NotFoundError(_) => "NOT_FOUND",
            LuserError::AlreadyExistsError(_) => "ALREADY_EXISTS",
            LuserError::RateLimitError => "RATE_LIMIT",
            LuserError::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            LuserError::UnknownError(_) => "UNKNOWN_ERROR",
        };
        
        crate::ApiError::new(code, &self.to_string(), self.http_status_code())
    }
}

impl From<sqlx::Error> for LuserError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => LuserError::NotFoundError("数据不存在".to_string()),
            _ => LuserError::DatabaseError(err.to_string()),
        }
    }
}

impl From<validator::ValidationErrors> for LuserError {
    fn from(err: validator::ValidationErrors) -> Self {
        LuserError::ValidationError(err.to_string())
    }
}

impl From<serde_json::Error> for LuserError {
    fn from(err: serde_json::Error) -> Self {
        LuserError::ValidationError(format!("JSON解析错误: {}", err))
    }
}

impl From<std::io::Error> for LuserError {
    fn from(err: std::io::Error) -> Self {
        LuserError::FileError(err.to_string())
    }
}

impl From<reqwest::Error> for LuserError {
    fn from(err: reqwest::Error) -> Self {
        LuserError::NetworkError(err.to_string())
    }
}

impl From<uuid::Error> for LuserError {
    fn from(err: uuid::Error) -> Self {
        LuserError::ValidationError(format!("UUID错误: {}", err))
    }
}

impl From<chrono::ParseError> for LuserError {
    fn from(err: chrono::ParseError) -> Self {
        LuserError::ValidationError(format!("时间解析错误: {}", err))
    }
}

impl From<base64::DecodeError> for LuserError {
    fn from(err: base64::DecodeError) -> Self {
        LuserError::ValidationError(format!("Base64解码错误: {}", err))
    }
}

impl From<url::ParseError> for LuserError {
    fn from(err: url::ParseError) -> Self {
        LuserError::ValidationError(format!("URL解析错误: {}", err))
    }
}