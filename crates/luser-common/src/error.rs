//! 统一错误处理模块

use luser_config::ConfigError;
use thiserror::Error;
use serde::Serialize;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use tracing::{error, warn, info};
use serde_json::Value;
use std::convert::Infallible;

/// 应用统一错误类型
#[derive(Error, Debug)]
pub enum AppError {
    // 认证相关错误
    #[error("认证失败: {0}")]
    Unauthorized(String),
    
    #[error("权限不足: {0}")]
    Forbidden(String),
    
    #[error("令牌已过期: {0}")]
    TokenExpired(String),
    
    #[error("无效的令牌: {0}")]
    InvalidToken(String),
    
    // 业务逻辑错误
    #[error("资源不存在: {0}")]
    NotFound(String),
    
    #[error("请求参数错误: {0}")]
    BadRequest(String),
    
    #[error("验证失败: {0}")]
    ValidationError(String),
    
    #[error("业务逻辑错误: {0}")]
    BusinessError(String),
    
    #[error("重复操作: {0}")]
    DuplicateError(String),
    
    #[error("超出限制: {0}")]
    LimitExceeded(String),
    
    #[error("资源冲突: {0}")]
    Conflict(String),
    
    // 系统错误
    #[error("内部服务器错误: {0}")]
    InternalServerError(String),
    
    #[error("数据库错误: {0}")]
    DatabaseError(String),
    
    #[error("配置错误: {0}")]
    ConfigError(String),
    
    #[error("加密错误: {0}")]
    EncryptionError(String),
    
    #[error("外部服务错误: {0}")]
    ExternalServiceError(String),
    
    #[error("IO错误: {0}")]
    IoError(String),
    
    #[error("序列化错误: {0}")]
    SerializationError(String),
    
    #[error("反序列化错误: {0}")]
    DeserializationError(String),
    
    #[error("网络错误: {0}")]
    NetworkError(String),
    
    #[error("请求超时: {0}")]
    TimeoutError(String),
}

impl AppError {
    /// 获取HTTP状态码
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::TokenExpired(_) => StatusCode::UNAUTHORIZED,
            AppError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::ValidationError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::BusinessError(_) => StatusCode::BAD_REQUEST,
            AppError::DuplicateError(_) => StatusCode::CONFLICT,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::LimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::TimeoutError(_) => StatusCode::REQUEST_TIMEOUT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    
    /// 获取错误代码
    pub fn error_code(&self) -> &'static str {
        match self {
            AppError::Unauthorized(_) => "UNAUTHORIZED",
            AppError::Forbidden(_) => "FORBIDDEN",
            AppError::TokenExpired(_) => "TOKEN_EXPIRED",
            AppError::InvalidToken(_) => "INVALID_TOKEN",
            AppError::NotFound(_) => "NOT_FOUND",
            AppError::BadRequest(_) => "BAD_REQUEST",
            AppError::ValidationError(_) => "VALIDATION_ERROR",
            AppError::BusinessError(_) => "BUSINESS_ERROR",
            AppError::DuplicateError(_) => "DUPLICATE_ERROR",
            AppError::LimitExceeded(_) => "LIMIT_EXCEEDED",
            AppError::Conflict(_) => "CONFLICT",
            AppError::InternalServerError(_) => "INTERNAL_SERVER_ERROR",
            AppError::DatabaseError(_) => "DATABASE_ERROR",
            AppError::ConfigError(_) => "CONFIG_ERROR",
            AppError::EncryptionError(_) => "ENCRYPTION_ERROR",
            AppError::ExternalServiceError(_) => "EXTERNAL_SERVICE_ERROR",
            AppError::IoError(_) => "IO_ERROR",
            AppError::SerializationError(_) => "SERIALIZATION_ERROR",
            AppError::DeserializationError(_) => "DESERIALIZATION_ERROR",
            AppError::NetworkError(_) => "NETWORK_ERROR",
            AppError::TimeoutError(_) => "TIMEOUT_ERROR",
        }
    }
    
    /// 转换为JSON格式
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "code": self.error_code(),
            "message": self.to_string(),
            "status": self.status_code().as_u16(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
    }
    
    /// 记录错误日志
    fn log(&self) {
        let status_code = self.status_code().as_u16();
        match status_code {
            401 | 403 => warn!("认证错误: {} - {}", self.error_code(), self),
            400..=499 => info!("客户端错误: {} - {}", self.error_code(), self),
            500..=599 => error!("服务器错误: {} - {}", self.error_code(), self),
            _ => error!("未知错误: {} - {}", self.error_code(), self),
        }
    }
    
    /// 是否为客户端错误 (4xx)
    pub fn is_client_error(&self) -> bool {
        let code = self.status_code().as_u16();
        (400..500).contains(&code)
    }
    
    /// 是否为服务器错误 (5xx)
    pub fn is_server_error(&self) -> bool {
        let code = self.status_code().as_u16();
        (500..600).contains(&code)
    }
}

/// API错误响应详情
#[derive(Serialize, Debug, Clone)]
pub struct ErrorDetail {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// API错误响应
#[derive(Serialize, Debug)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: ErrorDetail,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 记录日志
        self.log();
        
        let response = ErrorResponse {
            success: false,
            error: ErrorDetail {
                code: self.error_code(),
                message: self.to_string(),
                details: None,
                request_id: None, // 可以从请求上下文获取
                field: None,
            },
            timestamp: chrono::Utc::now(),
        };
        
        (self.status_code(), Json(response)).into_response()
    }
}

/// 便捷构造函数
impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
    
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }
    
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }
    
    pub fn not_found(resource: &str) -> Self {
        Self::NotFound(format!("{}不存在", resource))
    }
    
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }
    
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::ValidationError(msg.into())
    }
    
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::InternalServerError(msg.into())
    }
    
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::TimeoutError(msg.into())
    }
    
    pub fn limit_exceeded(msg: impl Into<String>) -> Self {
        Self::LimitExceeded(msg.into())
    }
    
    pub fn field_validation(field: &str, msg: impl Into<String>) -> Self {
        Self::ValidationError(format!("字段 {} 验证失败: {}", field, msg.into()))
    }
}

/// 结果类型别名
pub type Result<T> = std::result::Result<T, AppError>;



/// 错误转换 - sqlx
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AppError::NotFound("记录不存在".to_string()),
            sqlx::Error::Database(db_err) => {
                if db_err.is_unique_violation() {
                    AppError::DuplicateError("记录已存在".to_string())
                } else if db_err.is_foreign_key_violation() {
                    AppError::DatabaseError("外键约束错误".to_string())
                } else if db_err.is_check_violation() {
                    AppError::ValidationError("数据检查失败".to_string())
                } else {
                    AppError::DatabaseError(format!("数据库错误: {}", db_err))
                }
            }
            sqlx::Error::PoolTimedOut => AppError::DatabaseError("数据库连接池超时".to_string()),
            sqlx::Error::PoolClosed => AppError::DatabaseError("数据库连接池已关闭".to_string()),
            _ => AppError::DatabaseError(format!("数据库操作失败: {}", err)),
        }
    }
}

/// 错误转换 - redis
impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        use redis::ErrorKind;
        
        match err.kind() {
            ErrorKind::Io => AppError::NetworkError("Redis IO错误".to_string()),
            ErrorKind::Client => AppError::ExternalServiceError("Redis客户端错误".to_string()),
            _ => AppError::ExternalServiceError(format!("Redis错误: {}", err)),
        }
    }
}

/// 错误转换 - reqwest
impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            AppError::TimeoutError("请求超时".to_string())
        } else if err.is_connect() {
            AppError::NetworkError("连接失败".to_string())
        } else if err.is_decode() {
            AppError::DeserializationError("响应解析失败".to_string())
        } else {
            AppError::ExternalServiceError(format!("HTTP请求失败: {}", err))
        }
    }
}

/// 错误转换 - validator
impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        let message = err
            .field_errors()
            .iter()
            .map(|(field, errors)| {
                let err_msg = errors
                    .iter()
                    .find_map(|e| e.message.as_ref())
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "格式错误".to_string());
                format!("{}: {}", field, err_msg)
            })
            .collect::<Vec<_>>()
            .join(", ");
        
        AppError::validation(format!("数据验证失败: {}", message))
    }
}

/// 错误转换 - serde_json
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::bad_request(format!("JSON格式错误: {}", err))
    }
}

/// 错误转换 - uuid
impl From<uuid::Error> for AppError {
    fn from(err: uuid::Error) -> Self {
        AppError::bad_request(format!("ID格式错误: {}", err))
    }
}

/// 错误转换 - argon2
impl From<argon2::Error> for AppError {
    fn from(_: argon2::Error) -> Self {
        AppError::internal("密码加密失败")
    }
}

/// 错误转换 - jsonwebtoken
impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                AppError::TokenExpired("登录已过期，请重新登录".to_string())
            }
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                AppError::InvalidToken("登录信息无效".to_string())
            }
            _ => AppError::Unauthorized("登录验证失败".to_string()),
        }
    }
}

/// 错误转换 - std::io::Error
impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::IoError(format!("IO错误: {}", err))
    }
}

/// 错误转换 - chrono::ParseError
impl From<chrono::ParseError> for AppError {
    fn from(err: chrono::ParseError) -> Self {
        AppError::BadRequest(format!("时间格式错误: {}", err))
    }
}

/// 错误转换 - std::env::VarError
impl From<std::env::VarError> for AppError {
    fn from(err: std::env::VarError) -> Self {
        AppError::ConfigError(format!("环境变量错误: {}", err))
    }
}

/// 错误转换 - std::num::ParseIntError
impl From<std::num::ParseIntError> for AppError {
    fn from(err: std::num::ParseIntError) -> Self {
        AppError::BadRequest(format!("数字解析错误: {}", err))
    }
}

/// 错误转换 - std::num::ParseFloatError
impl From<std::num::ParseFloatError> for AppError {
    fn from(err: std::num::ParseFloatError) -> Self {
        AppError::BadRequest(format!("浮点数解析错误: {}", err))
    }
}

/// 错误转换 - std::str::ParseBoolError
impl From<std::str::ParseBoolError> for AppError {
    fn from(err: std::str::ParseBoolError) -> Self {
        AppError::BadRequest(format!("布尔值解析错误: {}", err))
    }
}
impl From<ConfigError> for AppError {
    fn from(err: ConfigError) -> Self {
        AppError::ConfigError(err.to_string())
    }
}
/// 错误处理工具扩展
pub trait ResultExt<T> {
    /// 添加上下文信息
    fn context(self, context: &str) -> Result<T>;
    
    /// 处理找不到资源的情况
    fn or_not_found(self, resource: &str) -> Result<T>;
    
    /// 处理可选值，如果为None则返回NotFound错误
    fn ok_or_not_found(self, resource: &str) -> Result<T>;
    
    /// 添加请求ID上下文
    fn with_request_id(self, request_id: &str) -> Result<T>;
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
where
    E: Into<AppError>,
{
    fn context(self, context: &str) -> Result<T> {
        self.map_err(|e| {
            let err = e.into();
            match err {
                AppError::InternalServerError(msg) => AppError::internal(format!("{}: {}", context, msg)),
                _ => {
                    // 为其他错误类型添加上下文
                    AppError::InternalServerError(format!("{}: {}", context, err))
                }
            }
        })
    }
    
    fn or_not_found(self, resource: &str) -> Result<T> {
        self.map_err(|e| {
            let err = e.into();
            if let AppError::NotFound(_) = err {
                AppError::not_found(resource)
            } else {
                err
            }
        })
    }
    
    fn ok_or_not_found(self, resource: &str) -> Result<T> {
       self.or_else(|_| Err(AppError::not_found(resource)))
    }
    
    fn with_request_id(self, request_id: &str) -> Result<T> {
        // 这个实现比较简化，实际使用时可能需要更复杂的处理
        self.map_err(|e| {
            let mut err = e.into();
            // 这里可以添加请求ID到错误详情
            // 由于AppError是枚举，可能需要修改结构来支持请求ID
            err
        })
    }
}

/// 为Option实现ResultExt
impl<T> ResultExt<T> for Option<T> {
    fn context(self, context: &str) -> Result<T> {
        self.ok_or_else(|| AppError::internal(format!("{}: 值为空", context)))
    }
    
    fn or_not_found(self, resource: &str) -> Result<T> {
        self.ok_or_else(|| AppError::not_found(resource))
    }
    
    fn ok_or_not_found(self, resource: &str) -> Result<T> {
        self.ok_or_else(|| AppError::not_found(resource))
    }
    
    fn with_request_id(self, _request_id: &str) -> Result<T> {
        // 对于Option，请求ID处理不太适用
        self.ok_or_else(|| AppError::internal("值为空"))
    }
}

/// 辅助函数：从错误链中提取根原因
pub fn root_cause(err: &(dyn std::error::Error + 'static)) -> String {
    let mut cause = err.source();
    let mut current_err = err;
    
    while let Some(source) = cause {
        current_err = source;
        cause = source.source();
    }
    
    current_err.to_string()
}

/// 辅助函数：格式化错误链
pub fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut result = String::new();
    let mut current: Option<&dyn std::error::Error> = Some(err);
    let mut indent = 0;
    
    while let Some(err) = current {
        if indent > 0 {
            result.push_str(&"  ".repeat(indent));
            result.push_str("-> ");
        }
        result.push_str(&err.to_string());
        result.push('\n');
        current = err.source();
        indent += 1;
    }
    
    result
}