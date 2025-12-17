项目结构
luser-backend/
├── Cargo.toml                    # Workspace根配置

├── .env.example                 # 环境变量示例
├── .env                         # 本地环境变量（不提交）
├── docker-compose.yml           # 开发环境Docker配置
├── docker-compose.prod.yml      # 生产环境Docker配置
├── nginx/
│   ├── nginx.conf              # Nginx配置
│   └── conf.d/
│       ├── api.conf            # API服务配置
│       └── admin.conf          # 管理后台配置
├── scripts/
│   ├── init-dev.sh             # 开发环境初始化
│   ├── init-prod.sh            # 生产环境部署
│   ├── run-migrations.sh       # 数据库迁移
│   ├── backup-database.sh      # 数据库备份
│   └── monitor-services.sh     # 服务监控
└── crates/
    ├── luser-common/           # 公共库
    ├── luser-db/               # 数据库模型和迁移
    ├── luser-config/           # 配置管理
    ├── luser-tencent-vod/      # 腾讯云VOD适配器
    ├── luser-aliyun-vod/       # 阿里云VOD适配器
    ├── luser-alipay/           # 支付宝适配器
    ├── luser-wechatpay/        # 微信支付适配器
    ├── luser-cloud/            # 云服务抽象层
    ├── luser-payment/          # 支付抽象层
    ├── luser-core/             # 核心业务逻辑
    ├── luser-api/              # 主API服务
    └── luser-admin/            # 管理后台API

Config 模块目录结构
crates/luser-config/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── config.rs              # 主要配置结构体
│   ├── loader.rs              # 配置加载器
│   ├── manager.rs             # 配置管理器
│   ├── validator.rs           # 配置验证器
│   ├── merger.rs             # 配置合并器
│   ├── init.rs             # 配置初始化
│   ├── encryption.rs          # 配置加密
│   ├── database.rs             # 配置数据库操作
│   ├── watcher.rs             # 配置监控和热重载
│   ├── error.rs               # 错误定义
│   ├── constants.rs           # 常量定义

└── config/                    # 配置文件目录
    ├── default.toml           # 默认配置
    ├── development.toml       # 开发环境配置
    ├── production.toml        # 生产环境配置
    └── test.toml              # 测试环境配置完整项目结构

luser-common (公共库)

luser-common/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs              # 导出模块
    ├── error.rs            # 公共错误类型和结果
    ├── types.rs            # 公共类型定义
    ├── constants.rs        # 常量定义
    ├── utils/
    │   ├── mod.rs
    │   ├── time.rs         # 时间处理
    │   ├── crypto.rs       # 加密工具
    │   ├── validation.rs   # 数据验证
    │   ├── string.rs       # 字符串处理
    │   └── logger.rs       # 日志工具
    ├── traits/
    │   ├── mod.rs
    │   ├── service.rs      # 服务特征
    │   ├── repository.rs   # 仓储特征
    │   └── cache.rs        # 缓存特征
    ├── enums/
    │   ├── mod.rs
    │   ├── user.rs         # 用户相关枚举
    │   ├── video.rs        # 视频相关枚举
    │   ├── order.rs        # 订单相关枚举
    │   └── payment.rs      # 支付相关枚举
    ├── dto/
    │   ├── mod.rs
    │   ├── request.rs      # 请求DTO
    │   ├── response.rs     # 响应DTO
    │   └── query.rs        # 查询DTO
    └── middleware/
        ├── mod.rs
        ├── auth.rs         # 认证中间件
        ├── rate_limit.rs   # 限流中间件
        ├── cors.rs         # CORS中间件
        └── logging.rs      # 日志中间件
luser-db(数据库)
crates/luser-db/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── global.rs          # 全局数据库管理
│   ├── pool.rs           # 连接池管理
│   ├── model.rs          # Model基类和宏
│   ├── db.rs            # Db类，提供链式调用
│   ├── query.rs         # 查询构建器
│   ├── transaction.rs    # 事务管理
│   ├── pagination.rs     # 分页支持
│   ├── error.rs         # 错误类型
│   ├── enums.rs         # 枚举定义
│   ├── types.rs         # 自定义类型
│   ├── migrator.rs      # 迁移管理
│   └── macros/          # 过程宏
│       ├── mod.rs
│       ├── model.rs     # Model宏
│       └── column.rs    # Column宏
└── migrations/              # 迁移文件

luser-common 公共库详细实现
1.1 error.rs - 完整的错误定义
//! 统一错误处理模块
use thiserror::Error;


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

luser-config 配置库详细实现
config.rs
/// 应用主配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(rename_all = "kebab-case")]
pub struct AppConfig {
    /// 服务器配置
    #[serde(default = "ServerConfig::default")]
    pub server: ServerConfig,
    
    /// 数据库配置
    #[serde(default = "DatabaseConfig::default")]
    pub database: DatabaseConfig,
    
    /// Redis配置
    #[serde(default = "RedisConfig::default")]
    pub redis: RedisConfig,
    
    /// JWT配置
    #[serde(default = "JwtConfig::default")]
    pub jwt: JwtConfig,
    
    /// 加密配置
    #[serde(default = "EncryptionConfig::default")]
    pub encryption: EncryptionConfig,
    
    /// 缓存配置
    #[serde(default = "CacheConfig::default")]
    pub cache: CacheConfig,
    
    /// 特性开关
    #[serde(default = "FeatureConfig::default")]
    pub features: FeatureConfig,
    
    /// 扩展配置
    #[serde(default, flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerConfig {
    /// 服务器主机地址
    #[serde(default = "default_host")]
    #[validate(length(min = 1))]
    pub host: String,
    
    /// 服务器端口
    #[serde(default = "default_port")]
    #[validate(range(min = 1, max = 65535))]
    pub port: u16,
    
}

/// 数据库配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DatabaseConfig {
    /// 数据库连接URL
    #[serde(default = "default_database_url")]
    #[validate(url)]
    pub url: String,
    /// 最大连接数
    #[serde(default = "default_max_connections")]
    #[validate(range(min = 1, max = 100))]
    pub max_connections: u32,
    
    /// 最小连接数
    #[serde(default = "default_min_connections")]
    #[validate(range(min = 0, max = 50))]
    pub min_connections: u32,
    
    /// 连接超时时间（秒）
    #[serde(default = "default_connection_timeout")]
     #[validate(range(min = 1, max = 300))]
    pub connection_timeout: u64,
    
    /// 空闲连接超时时间（秒）
    #[serde(default = "default_idle_timeout")]
     #[validate(range(min = 1, max = 3600))]
    pub idle_timeout: u64,
    
    /// 连接最大生存时间（秒）
    #[serde(default = "default_max_lifetime")]
    #[validate(range(min = 1, max = 7200))]
    pub max_lifetime: u64,
    
    /// 启用连接健康检查
    #[serde(default = "default_enable_health_check")]
    pub enable_health_check: bool,
    
    /// 启用SSL连接
    #[serde(default = "default_enable_ssl")]
    pub enable_ssl: bool,
    
    /// SSL CA证书路径
    #[serde(default)]
    pub ssl_ca_cert_path: Option<String>,
    
    /// SSL客户端证书路径
    #[serde(default)]
    pub ssl_client_cert_path: Option<String>,
    
    /// SSL客户端密钥路径
    #[serde(default)]
    pub ssl_client_key_path: Option<String>,
    
    /// 连接池名称
    #[serde(default = "default_pool_name")]
    #[validate(length(min = 1))]
    pub pool_name: String,
}

/// Redis配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RedisConfig {
    /// Redis连接URL
    #[serde(default = "default_redis_url")]
   #[validate(url)]
    pub url: String,
    
    /// 连接池大小
    #[serde(default = "default_redis_pool_size")]
    #[validate(range(min = 1, max = 100))]
    pub pool_size: usize,
    
    /// 默认TTL（秒）
    #[serde(default = "default_redis_ttl")]
    #[validate(range(min = 1))]
    pub default_ttl: u64,
    
    /// 连接超时时间（秒）
    #[serde(default = "default_redis_connect_timeout")]
    #[validate(range(min = 1, max = 300))]
    pub connect_timeout: u64,
    
    /// 命令超时时间（秒）
    #[serde(default = "default_redis_command_timeout")]
    #[validate(range(min = 1, max = 300))]
    pub command_timeout: u64,
    
    /// 启用TLS
    #[serde(default = "default_redis_enable_tls")]
    pub enable_tls: bool,
    
    /// 集群模式
    #[serde(default = "default_redis_cluster_mode")]
    pub cluster_mode: bool,
    
    /// 哨兵模式
    #[serde(default = "default_redis_sentinel_mode")]
    pub sentinel_mode: bool,
    
    /// 哨兵主节点名称
    #[serde(default)]
    pub sentinel_master_name: Option<String>,
    
    /// 哨兵节点列表
    #[serde(default)]
    pub sentinel_nodes: Vec<String>,
    
    /// 密码（加密存储）
    #[serde(default)]
    pub password: Option<String>,
    
    /// 数据库编号
    #[serde(default = "default_redis_database")]
    pub database: u8,
}
...其他配置
impl AppConfig {
    /// 获取服务器监听地址
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
    
    /// 获取数据库连接池配置
    pub fn database_pool_config(&self) -> sqlx::postgres::PgPoolOptions {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(self.database.max_connections)
            .min_connections(self.database.min_connections)
            .acquire_timeout(Duration::from_secs(self.database.connection_timeout))
            .idle_timeout(Duration::from_secs(self.database.idle_timeout))
            .max_lifetime(Duration::from_secs(self.database.max_lifetime))
    }
    
    
    
    /// 检查配置值是否已加密
    pub fn is_encrypted(&self, key_path: &str) -> bool {
        // 尝试从全局加密器检查
        if let Ok(encryptor) = crate::encryption::get_global_encryptor() {
            let value = self.get_value_by_path(key_path);
            if let Ok(value_str) = value {
                return encryptor.is_encrypted_value(&value_str);
            }
        }
        false
    }
    /// 根据路径获取配置值
    fn get_value_by_path(&self, path: &str) -> ConfigResult<String> {
        let parts: Vec<&str> = path.split('.').collect();
        
        match parts.as_slice() {
            ["database", "url"] => Ok(self.database.url.clone()),
            ["redis", "password"] => Ok(self.redis.password.clone().unwrap_or_default()),
            ["redis", "url"] => Ok(self.redis.url.clone()),
           
        }
    }
    /// 加密敏感配置
    pub fn encrypt_sensitive_fields(&mut self) -> ConfigResult<()> {
        let encryptor = crate::encryption::get_global_encryptor()?;
        encryptor.encrypt_config(self)
    }
    
    /// 解密敏感配置
    pub fn decrypt_sensitive_fields(&mut self) -> ConfigResult<()> {
        let encryptor = crate::encryption::get_global_encryptor()?;
        encryptor.decrypt_config(self)
    }
    
    /// 获取解密后的数据库URL
    pub fn get_decrypted_database_url(&self) -> ConfigResult<String> {
        let encryptor = crate::encryption::get_global_encryptor()?;
        
        if encryptor.is_encrypted_value(&self.database.url) {
            encryptor.decrypt_database_url(&self.database.url)
        } else {
            Ok(self.database.url.clone())
        }
    }
    
    /// 获取解密后的Redis密码
    pub fn get_decrypted_redis_password(&self) -> ConfigResult<Option<String>> {
        if let Some(password) = &self.redis.password {
            let encryptor = crate::encryption::get_global_encryptor()?;
            
            if encryptor.is_encrypted_value(password) {
                Ok(Some(encryptor.decrypt_config_value("redis.password", password)?))
            } else {
                Ok(Some(password.clone()))
            }
        } else {
            Ok(None)
        }
    }
    
   
   
}
init.rs

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


luser-db(数据库代码实现)
//! LUSER 数据库模块
//! 
//! 提供全局数据库管理、ActiveRecord模式、链式调用API

pub mod pool;
pub mod global;
pub mod model;
pub mod db;
pub mod query;
pub mod transaction;
pub mod pagination;
pub mod enums;
pub mod types;
pub mod migrator;


#[cfg(feature = "model-macros")]
pub mod macros;



use luser_common::AppError;
// 重新导出常用类型
pub use model::{Model, BaseModel, BaseModelWithId};
pub use db::Db;
pub use query::QueryBuilder;
pub use transaction::{TransactionManager, execute_transaction};


/// 数据库初始化
pub async fn init() -> Result<(), AppError> {
    #[cfg(feature = "global")]
    {
        global::init_from_env().await?;
    }
    
    Ok(())
}



/// 便捷函数：查询构建
pub fn query<T: Model>() -> QueryBuilder<T> {
    #[cfg(feature = "global")]
    {
        global::query::<T>()
    }
    #[cfg(not(feature = "global"))]
    {
        panic!("Global feature must be enabled to use query() function")
    }
}

/// 便捷函数：获取模型实例
pub fn model<T: Model>() -> T {
    T::default()
}

/// 便捷函数：执行原始SQL
pub async fn execute_sql(sql: &str) -> Result<u64, AppError> {
    #[cfg(feature = "global")]
    {
        global::execute(sql).await
    }
    #[cfg(not(feature = "global"))]
    {
        panic!("Global feature must be enabled to use execute_sql() function")
    }
}

transaction.rs

/// 事务管理器
#[derive(Debug, Clone)]
pub struct TransactionManager {
    pool: Pool<Postgres>,
}

impl TransactionManager {
    /// 创建新的事务管理器
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
    
    /// 开始事务
    pub async fn begin(&self) -> Result<Transaction<'_, Postgres>, LuserError> {
        self.pool
            .begin()
            .await
            .map_err(|e| LuserError::DatabaseError(format!("Failed to begin transaction: {}", e)))
    }
    
    /// 执行事务
    pub async fn execute<F, T, E>(&self, f: F) -> Result<T, LuserError>
    where
        F: FnOnce(&mut Transaction<'_, Postgres>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
        E: Into<LuserError>,
    {
        let mut tx = self.begin().await?;
        
        match f(&mut tx).await {
            Ok(result) => {
                tx.commit()
                    .await
                    .map_err(|e| LuserError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;
                Ok(result)
            }
            Err(e) => {
                tx.rollback()
                    .await
                    .map_err(|e| LuserError::DatabaseError(format!("Failed to rollback transaction: {}", e)))?;
                Err(e.into())
            }
        }
    }
}

/// 事务上下文
pub struct TransactionContext {
    transaction: Mutex<Option<Transaction<'static, Postgres>>>,
}

impl TransactionContext {
    /// 创建新的事务上下文
    pub fn new() -> Self {
        Self {
            transaction: Mutex::new(None),
        }
    }
    
    /// 开始事务
    pub async fn begin(&self) -> Result<(), LuserError> {
        let mut tx_guard = self.transaction.lock().await;
        
        if tx_guard.is_some() {
            return Err(LuserError::DatabaseError("Transaction already started".to_string()));
        }
        
        let pool = crate::global::db().raw_pool();
        let tx = pool.begin().await
            .map_err(|e| LuserError::DatabaseError(format!("Failed to begin transaction: {}", e)))?;
        
        // 安全转换：我们知道事务生命周期会被管理
        let tx = unsafe {
            std::mem::transmute::<Transaction<'_, Postgres>, Transaction<'static, Postgres>>(tx)
        };
        
        *tx_guard = Some(tx);
        Ok(())
    }
    
    /// 提交事务
    pub async fn commit(&self) -> Result<(), LuserError> {
        let mut tx_guard = self.transaction.lock().await;
        
        if let Some(tx) = tx_guard.take() {
            tx.commit().await
                .map_err(|e| LuserError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;
            Ok(())
        } else {
            Err(LuserError::DatabaseError("No transaction to commit".to_string()))
        }
    }
    
    /// 回滚事务
    pub async fn rollback(&self) -> Result<(), LuserError> {
        let mut tx_guard = self.transaction.lock().await;
        
        if let Some(tx) = tx_guard.take() {
            tx.rollback().await
                .map_err(|e| LuserError::DatabaseError(format!("Failed to rollback transaction: {}", e)))?;
            Ok(())
        } else {
            Err(LuserError::DatabaseError("No transaction to rollback".to_string()))
        }
    }
    
    /// 获取事务引用
    pub async fn get_transaction(&self) -> Result<Transaction<'static, Postgres>, LuserError> {
        let tx_guard = self.transaction.lock().await;
        
        if let Some(tx) = tx_guard.as_ref() {
            // 克隆事务（需要特殊处理）
            // 注意：实际使用中可能需要更复杂的处理
            Ok(tx.clone())
        } else {
            Err(LuserError::DatabaseError("No active transaction".to_string()))
        }
    }
    
    /// 检查是否在事务中
    pub async fn in_transaction(&self) -> bool {
        let tx_guard = self.transaction.lock().await;
        tx_guard.is_some()
    }
}

/// 全局事务管理器
pub fn transaction_manager() -> &'static TransactionManager {
    &crate::global::db().transaction_manager()
}

/// 执行事务的便捷函数
pub async fn execute_transaction<F, T, E>(f: F) -> Result<T, LuserError>
where
    F: FnOnce(&mut Transaction<'_, Postgres>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
    E: Into<LuserError>,
{
    transaction_manager().execute(f).await
}

/// 事务宏
#[macro_export]
macro_rules! transaction {
    ($code:block) => {
        {
            use $crate::transaction::execute_transaction;
            
            execute_transaction(|tx| {
                Box::pin(async move {
                    let result = $code;
                    result
                })
            }).await
        }
    };
}
query.rs
//! 查询构建器，支持链式调用

use std::collections::HashMap;
use luser_common::{LuserError, PaginatedResult};
use sqlx::{Pool, Postgres, Row};
use serde_json::Value as JsonValue;

use crate::model::Model;

/// 查询构建器
#[derive(Debug, Clone)]
pub struct QueryBuilder<T: Model> {
    /// 数据库连接池，用于执行最终查询
    pool: Pool<Postgres>,
    
    /// SELECT子句的列列表
    /// 例如："id, name, email" 或 "*"
    select_columns: String,
    
    /// WHERE子句的条件表达式集合
    where_conditions: Vec<String>,
    
    /// WHERE子句的参数值集合
    /// 使用JsonValue包装以支持多种数据类型
    where_params: Vec<JsonValue>,
    
    /// ORDER BY子句
    order_by: Option<String>,
    
    /// LIMIT子句，限制返回记录数
    limit: Option<u64>,
    
    /// OFFSET子句，指定跳过的记录数
    offset: Option<u64>,
    
    /// JOIN子句集合
    /// 例如：["INNER JOIN posts ON users.id = posts.user_id"]
    joins: Vec<String>,
    
    /// GROUP BY子句
    /// 例如："department_id, status"
    group_by: Option<String>,
    
    /// HAVING子句（需与GROUP BY配合使用）
    /// 例如："COUNT(*) > 1"
    having: Option<String>,
    
    /// 类型标记，用于在编译时关联泛型参数T
    /// 使结构体能够保留泛型类型信息而不实际持有该类型的值
    _marker: std::marker::PhantomData<T>,
}

impl<T: Model> QueryBuilder<T> {
    /// 创建新的查询构建器
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self {
            pool,
            select_columns: T::all_fields(),
            where_conditions: Vec::new(),
            where_params: Vec::new(),
            order_by: None,
            limit: None,
            offset: None,
            joins: Vec::new(),
            group_by: None,
            having: None,
            _marker: std::marker::PhantomData,
        }
    }
    
    /// 设置查询字段
    pub fn select(mut self, columns: &str) -> Self {
        self.select_columns = columns.to_string();
        self
    }
    
    /// 添加WHERE条件
    pub fn r#where(mut self, condition: &str) -> Self {
        self.where_conditions.push(condition.to_string());
        self
    }
    
    /// 添加带参数的WHERE条件
    pub fn where_param(mut self, condition: &str, param: JsonValue) -> Self {
        self.where_conditions.push(condition.to_string());
        self.where_params.push(param);
        self
    }
    
    /// 添加多个WHERE条件
    pub fn where_many(mut self, conditions: &[(&str, Option<JsonValue>)]) -> Self {
        for (condition, param) in conditions {
            self.where_conditions.push(condition.to_string());
            if let Some(param) = param {
                self.where_params.push(param.clone());
            }
        }
        self
    }
    
    /// 添加IN条件
    pub fn where_in(mut self, column: &str, values: Vec<JsonValue>) -> Self {
        if !values.is_empty() {
            let placeholders = (1..=values.len())
                .map(|i| format!("${}", self.where_params.len() + i))
                .collect::<Vec<_>>()
                .join(", ");
            
            self.where_conditions.push(format!("{} IN ({})", column, placeholders));
            self.where_params.extend(values);
        }
        self
    }
    
    /// 添加LIKE条件
    pub fn where_like(mut self, column: &str, pattern: &str) -> Self {
        self.where_conditions.push(format!("{} LIKE ${}", column, self.where_params.len() + 1));
        self.where_params.push(JsonValue::String(pattern.to_string()));
        self
    }
    
    /// 添加BETWEEN条件
    pub fn where_between(mut self, column: &str, start: JsonValue, end: JsonValue) -> Self {
        self.where_conditions.push(format!("{} BETWEEN ${} AND ${}", 
            column, 
            self.where_params.len() + 1,
            self.where_params.len() + 2
        ));
        self.where_params.push(start);
        self.where_params.push(end);
        self
    }
    
    /// 添加软删除条件
    pub fn where_not_deleted(mut self) -> Self {
        if T::soft_delete() {
            self.where_conditions.push("deleted_at IS NULL".to_string());
        }
        self
    }
    
    /// 添加排序
    pub fn order_by(mut self, order: &str) -> Self {
        self.order_by = Some(order.to_string());
        self
    }
    
    /// 设置限制
    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
    
    /// 设置偏移量
    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }
    
    /// 设置分页
    pub fn paginate(mut self, page: u64, per_page: u64) -> Self {
        self.limit = Some(per_page);
        self.offset = Some((page - 1) * per_page);
        self
    }
    
    /// 添加JOIN
    pub fn join(mut self, join_clause: &str) -> Self {
        self.joins.push(join_clause.to_string());
        self
    }
    
    /// 设置GROUP BY
    pub fn group_by(mut self, group_by: &str) -> Self {
        self.group_by = Some(group_by.to_string());
        self
    }
    
    /// 设置HAVING条件
    pub fn having(mut self, having: &str) -> Self {
        self.having = Some(having.to_string());
        self
    }
    
    /// 构建SQL语句
    pub fn build_sql(&self) -> String {
        let mut sql = format!("SELECT {} FROM {}", self.select_columns, T::table_name());
        
        // 添加JOIN
        if !self.joins.is_empty() {
            sql.push_str(&format!(" {}", self.joins.join(" ")));
        }
        
        // 添加WHERE条件
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        // 添加GROUP BY
        if let Some(group_by) = &self.group_by {
            sql.push_str(&format!(" GROUP BY {}", group_by));
        }
        
        // 添加HAVING
        if let Some(having) = &self.having {
            sql.push_str(&format!(" HAVING {}", having));
        }
        
        // 添加ORDER BY
        if let Some(order_by) = &self.order_by {
            sql.push_str(&format!(" ORDER BY {}", order_by));
        }
        
        // 添加LIMIT
        if let Some(limit) = self.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }
        
        // 添加OFFSET
        if let Some(offset) = self.offset {
            sql.push_str(&format!(" OFFSET {}", offset));
        }
        
        sql
    }
    
    /// 执行查询并返回结果
    pub async fn fetch_all(self) -> Result<Vec<T>, LuserError> {
        let sql = self.build_sql();
        
        let mut query_builder = sqlx::query_as::<_, T>(&sql);
        
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        query_builder
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LuserError::DatabaseError(e.to_string()))
    }
    
    /// 执行查询并返回第一条结果
    pub async fn fetch_one(self) -> Result<Option<T>, LuserError> {
        let sql = self.build_sql();
        
        let mut query_builder = sqlx::query_as::<_, T>(&sql);
        
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        query_builder
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LuserError::DatabaseError(e.to_string()))
    }
    
    /// 执行查询并返回分页结果
    pub async fn fetch_paginated(self, page: u64, per_page: u64) -> Result<PaginatedResult<T>, LuserError> {
        // 先获取总数
        let mut count_sql = format!("SELECT COUNT(*) FROM {}", T::table_name());
        
        if !self.where_conditions.is_empty() {
            count_sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut count_query = sqlx::query_as::<_, (i64,)>(&count_sql);
        
        for param in &self.where_params {
            count_query = count_query.bind(param);
        }
        
        let total: (i64,) = count_query
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LuserError::DatabaseError(e.to_string()))?;
        
        // 获取数据
        let mut data_sql = self.build_sql();
        
        // 确保有LIMIT和OFFSET
        if self.limit.is_none() {
            data_sql.push_str(&format!(" LIMIT {}", per_page));
        }
        
        if self.offset.is_none() {
            data_sql.push_str(&format!(" OFFSET {}", (page - 1) * per_page));
        }
        
        let mut data_query = sqlx::query_as::<_, T>(&data_sql);
        
        for param in self.where_params {
            data_query = data_query.bind(param);
        }
        
        let items = data_query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LuserError::DatabaseError(e.to_string()))?;
        
        Ok(PaginatedResult::new(items, total.0 as u64, page, per_page))
    }
    
    /// 执行查询并返回计数
    pub async fn count(self) -> Result<i64, LuserError> {
        let mut sql = format!("SELECT COUNT(*) FROM {}", T::table_name());
        
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut query_builder = sqlx::query_as::<_, (i64,)>(&sql);
        
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        let result: (i64,) = query_builder
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LuserError::DatabaseError(e.to_string()))?;
        
        Ok(result.0)
    }
    
    /// 执行更新操作
    pub async fn update(self, updates: &HashMap<String, JsonValue>) -> Result<u64, LuserError> {
        if updates.is_empty() {
            return Ok(0);
        }
        
        let set_clauses: Vec<String> = updates
            .iter()
            .enumerate()
            .map(|(i, (key, _))| format!("{} = ${}", key, i + 1))
            .collect();
        
        let mut sql = format!("UPDATE {} SET {}", T::table_name(), set_clauses.join(", "));
        
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut query_builder = sqlx::query(&sql);
        
        // 绑定更新参数
        for (_, value) in updates {
            query_builder = query_builder.bind(value);
        }
        
        // 绑定WHERE参数
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        let result = query_builder
            .execute(&self.pool)
            .await
            .map_err(|e| LuserError::DatabaseError(e.to_string()))?;
        
        Ok(result.rows_affected())
    }
    
    /// 执行删除操作
    pub async fn delete(self) -> Result<u64, LuserError> {
        let mut sql = format!("DELETE FROM {}", T::table_name());
        
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut query_builder = sqlx::query(&sql);
        
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        let result = query_builder
            .execute(&self.pool)
            .await
            .map_err(|e| LuserError::DatabaseError(e.to_string()))?;
        
        Ok(result.rows_affected())
    }
    
    /// 执行软删除操作
    pub async fn soft_delete(self) -> Result<u64, LuserError> {
        if !T::soft_delete() {
            return Err(LuserError::DatabaseError("Model does not support soft delete".to_string()));
        }
        
        let mut sql = format!("UPDATE {} SET deleted_at = $1, updated_at = $2", T::table_name());
        
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut query_builder = sqlx::query(&sql);
        
        // 绑定删除时间参数
        query_builder = query_builder.bind(chrono::Utc::now());
        query_builder = query_builder.bind(chrono::Utc::now());
        
        // 绑定WHERE参数
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        let result = query_builder
            .execute(&self.pool)
            .await
            .map_err(|e| LuserError::DatabaseError(e.to_string()))?;
        
        Ok(result.rows_affected())
    }
}

model.rs
//! Model基类，类似ActiveRecord模式

use std::collections::HashMap;
use std::marker::PhantomData;
use luser_common::{LuserError, PaginatedResult};
use serde::{Serialize, Deserialize};
use sqlx::{FromRow, Type, postgres::PgRow};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use async_trait::async_trait;

use crate::{
    db::Db,
    query::QueryBuilder,
};

/// Model trait，所有数据库模型必须实现
#[async_trait]
pub trait Model: Sized + Send + Sync + for<'r> FromRow<'r, PgRow> {
    /// 获取表名
    fn table_name() -> &'static str;
    
    /// 获取主键字段名
    fn primary_key() -> &'static str;
    
    /// 获取字段列表
    fn fields() -> Vec<&'static str>;
    
    /// 获取所有字段（带表名前缀）
    fn all_fields() -> String {
        Self::fields().join(", ")
    }
    
    /// 是否自动设置时间戳
    fn auto_timestamps() -> bool {
        true
    }
    
    /// 是否启用软删除
    fn soft_delete() -> bool {
        false
    }
    
    /// 创建默认实例
    fn default() -> Self;
    
    /// 保存当前实例（新增或更新）
    async fn save(&mut self) -> Result<&Self, LuserError>;
    
    /// 更新当前实例
    async fn update(&mut self) -> Result<&Self, LuserError>;
    
    /// 删除当前实例
    async fn delete(&self) -> Result<u64, LuserError>;
    
    /// 根据ID查找
    async fn find_by_id(id: impl Into<serde_json::Value> + Send) -> Result<Option<Self>, LuserError>;
    
    /// 根据条件查找第一个
    async fn find_first(where_clause: Option<&str>, params: Option<&[serde_json::Value]>) -> Result<Option<Self>, LuserError>;
    
    /// 根据条件查找所有
    async fn find_all(where_clause: Option<&str>, params: Option<&[serde_json::Value]>) -> Result<Vec<Self>, LuserError>;
    
    /// 分页查询
    async fn paginate(page: u64, per_page: u64, filters: Option<HashMap<String, serde_json::Value>>) -> Result<PaginatedResult<Self>, LuserError>;
    
    /// 获取关联查询构建器
    fn query() -> QueryBuilder<Self> {
        QueryBuilder::new(crate::global::db().raw_pool().clone())
    }
    
    /// 获取Db实例
    fn db() -> Db<Self> {
        Db::new(Self::default())
    }
}

/// 基础Model结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseModel {
    /// 创建时间
    pub created_at: Option<DateTime<Utc>>,
    
    /// 更新时间
    pub updated_at: Option<DateTime<Utc>>,
    
    /// 删除时间（软删除）
    pub deleted_at: Option<DateTime<Utc>>,
    
    /// 元数据
    pub metadata: Option<serde_json::Value>,
}

impl Default for BaseModel {
    fn default() -> Self {
        Self {
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            deleted_at: None,
            metadata: None,
        }
    }
}

/// 带ID的基础Model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseModelWithId {
    /// ID
    pub id: Uuid,
    
    /// 创建时间
    pub created_at: Option<DateTime<Utc>>,
    
    /// 更新时间
    pub updated_at: Option<DateTime<Utc>>,
    
    /// 删除时间（软删除）
    pub deleted_at: Option<DateTime<Utc>>,
    
    /// 元数据
    pub metadata: Option<serde_json::Value>,
}

impl Default for BaseModelWithId {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            deleted_at: None,
            metadata: None,
        }
    }
}

/// 状态枚举
pub trait ModelStatus: Type<sqlx::Postgres> + Clone + Send + Sync + 'static {
    fn default_status() -> Self;
    fn is_active(&self) -> bool;
    fn is_deleted(&self) -> bool;
}

/// 模型字段宏
#[macro_export]
macro_rules! model_fields {
    ($($field:ident: $type:ty,)*) => {
        paste::paste! {
            pub fn fields() -> Vec<&'static str> {
                vec![
                    $(stringify!($field),)*
                ]
            }
        }
    };
}

/// 定义Model宏
#[macro_export]
macro_rules! define_model {
    (
        $name:ident {
            $($field:ident: $type:ty $(=> $column:expr)?,)*
        }
    ) => {
        #[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
        pub struct $name {
            $(pub $field: $type,)*
        }
        
        #[async_trait::async_trait]
        impl $crate::model::Model for $name {
            fn table_name() -> &'static str {
                stringify!($name)
            }
            
            fn primary_key() -> &'static str {
                "id"
            }
            
            fn fields() -> Vec<&'static str> {
                vec![
                    $(stringify!($field),)*
                ]
            }
            
            fn default() -> Self {
                Self {
                    $($field: Default::default(),)*
                }
            }
            
            async fn save(&mut self) -> Result<&Self, LuserError> {
                // 检查是否为新记录
                let id_value: serde_json::Value = serde_json::to_value(&self.id)
                    .map_err(|e| LuserError::SerializationError(e.to_string()))?;
                
                if id_value.is_null() || (id_value.is_string() && id_value.as_str().unwrap().is_empty()) {
                    // 新增
                    self.id = Uuid::new_v4();
                    self.created_at = Some(Utc::now());
                    self.updated_at = Some(Utc::now());
                    
                    let query = format!(
                        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
                        Self::table_name(),
                        Self::fields().join(", "),
                        (0..Self::fields().len()).map(|i| format!("${}", i + 1)).collect::<Vec<_>>().join(", ")
                    );
                    
                    let mut query_builder = sqlx::query_as::<_, Self>(&query);
                    
                    // 绑定参数
                    $(
                        query_builder = query_builder.bind(&self.$field);
                    )*
                    
                    let result = query_builder
                        .fetch_one($crate::global::db().raw_pool())
                        .await
                        .map_err(|e| LuserError::CreateError(e.to_string()))?;
                    
                    *self = result;
                } else {
                    // 更新
                    self.updated_at = Some(Utc::now());
                    
                    let set_clause = Self::fields()
                        .iter()
                        .enumerate()
                        .map(|(i, field)| format!("{} = ${}", field, i + 1))
                        .collect::<Vec<_>>()
                        .join(", ");
                    
                    let query = format!(
                        "UPDATE {} SET {} WHERE {} = ${} RETURNING *",
                        Self::table_name(),
                        set_clause,
                        Self::primary_key(),
                        Self::fields().len() + 1
                    );
                    
                    let mut query_builder = sqlx::query_as::<_, Self>(&query);
                    
                    // 绑定参数
                    $(
                        query_builder = query_builder.bind(&self.$field);
                    )*
                    
                    query_builder = query_builder.bind(&self.id);
                    
                    let result = query_builder
                        .fetch_one($crate::global::db().raw_pool())
                        .await
                        .map_err(|e| LuserError::UpdateError(e.to_string()))?;
                    
                    *self = result;
                }
                
                Ok(self)
            }
            
            async fn update(&mut self) -> Result<&Self, LuserError> {
                self.save().await
            }
            
            async fn delete(&self) -> Result<u64, LuserError> {
                if Self::soft_delete() {
                    // 软删除
                    let query = format!(
                        "UPDATE {} SET deleted_at = $1 WHERE {} = $2",
                        Self::table_name(),
                        Self::primary_key()
                    );
                    
                    let result = sqlx::query(&query)
                        .bind(Utc::now())
                        .bind(&self.id)
                        .execute($crate::global::db().raw_pool())
                        .await
                        .map_err(|e| LuserError::DeleteError(e.to_string()))?;
                    
                    Ok(result.rows_affected())
                } else {
                    // 硬删除
                    let query = format!(
                        "DELETE FROM {} WHERE {} = $1",
                        Self::table_name(),
                        Self::primary_key()
                    );
                    
                    let result = sqlx::query(&query)
                        .bind(&self.id)
                        .execute($crate::global::db().raw_pool())
                        .await
                        .map_err(|e| LuserError::DeleteError(e.to_string()))?;
                    
                    Ok(result.rows_affected())
                }
            }
            
            async fn find_by_id(id: impl Into<serde_json::Value> + Send) -> Result<Option<Self>, LuserError> {
                let id_value = id.into();
                let query = format!(
                    "SELECT {} FROM {} WHERE {} = $1 {}",
                    Self::all_fields(),
                    Self::table_name(),
                    Self::primary_key(),
                    if Self::soft_delete() { "AND deleted_at IS NULL" } else { "" }
                );
                
                sqlx::query_as::<_, Self>(&query)
                    .bind(id_value)
                    .fetch_optional($crate::global::db().raw_pool())
                    .await
                    .map_err(|e| LuserError::QueryError(e.to_string()))
            }
            
            async fn find_first(where_clause: Option<&str>, params: Option<&[serde_json::Value]>) -> Result<Option<Self>, LuserError> {
                let mut query = format!(
                    "SELECT {} FROM {}",
                    Self::all_fields(),
                    Self::table_name()
                );
                
                if let Some(where_clause) = where_clause {
                    query.push_str(&format!(" WHERE {}", where_clause));
                }
                
                if Self::soft_delete() {
                    if where_clause.is_some() {
                        query.push_str(" AND deleted_at IS NULL");
                    } else {
                        query.push_str(" WHERE deleted_at IS NULL");
                    }
                }
                
                query.push_str(" LIMIT 1");
                
                let mut query_builder = sqlx::query_as::<_, Self>(&query);
                
                if let Some(params) = params {
                    for param in params {
                        query_builder = query_builder.bind(param);
                    }
                }
                
                query_builder
                    .fetch_optional($crate::global::db().raw_pool())
                    .await
                    .map_err(|e| LuserError::QueryError(e.to_string()))
            }
            
            async fn find_all(where_clause: Option<&str>, params: Option<&[serde_json::Value]>) -> Result<Vec<Self>, LuserError> {
                let mut query = format!(
                    "SELECT {} FROM {}",
                    Self::all_fields(),
                    Self::table_name()
                );
                
                if let Some(where_clause) = where_clause {
                    query.push_str(&format!(" WHERE {}", where_clause));
                }
                
                if Self::soft_delete() {
                    if where_clause.is_some() {
                        query.push_str(" AND deleted_at IS NULL");
                    } else {
                        query.push_str(" WHERE deleted_at IS NULL");
                    }
                }
                
                let mut query_builder = sqlx::query_as::<_, Self>(&query);
                
                if let Some(params) = params {
                    for param in params {
                        query_builder = query_builder.bind(param);
                    }
                }
                
                query_builder
                    .fetch_all($crate::global::db().raw_pool())
                    .await
                    .map_err(|e| LuserError::QueryError(e.to_string()))
            }
            
            async fn paginate(page: u64, per_page: u64, filters: Option<HashMap<String, serde_json::Value>>) -> Result<PaginatedResult<Self>, LuserError> {
                let mut query = format!("SELECT {} FROM {}", Self::all_fields(), Self::table_name());
                let mut count_query = format!("SELECT COUNT(*) FROM {}", Self::table_name());
                
                let mut conditions = Vec::new();
                let mut params: Vec<serde_json::Value> = Vec::new();
                
                if Self::soft_delete() {
                    conditions.push("deleted_at IS NULL".to_string());
                }
                
                if let Some(filters) = filters {
                    for (key, value) in filters {
                        conditions.push(format!("{} = ${}", key, params.len() + 1));
                        params.push(value);
                    }
                }
                
                if !conditions.is_empty() {
                    let where_clause = conditions.join(" AND ");
                    query.push_str(&format!(" WHERE {}", where_clause));
                    count_query.push_str(&format!(" WHERE {}", where_clause));
                }
                
                query.push_str(&format!(" LIMIT {} OFFSET {}", per_page, (page - 1) * per_page));
                
                // 获取总数
                let total: (i64,) = if params.is_empty() {
                    sqlx::query_as(&count_query)
                        .fetch_one($crate::global::db().raw_pool())
                        .await
                } else {
                    let mut query_builder = sqlx::query_as(&count_query);
                    for param in &params {
                        query_builder = query_builder.bind(param);
                    }
                    query_builder.fetch_one($crate::global::db().raw_pool()).await
                }
                .map_err(|e| LuserError::QueryError(e.to_string()))?;
                
                // 获取数据
                let items = if params.is_empty() {
                    sqlx::query_as::<_, Self>(&query)
                        .fetch_all($crate::global::db().raw_pool())
                        .await
                } else {
                    let mut query_builder = sqlx::query_as::<_, Self>(&query);
                    for param in &params {
                        query_builder = query_builder.bind(param);
                    }
                    query_builder.fetch_all($crate::global::db().raw_pool()).await
                }
                .map_err(|e| LuserError::QueryError(e.to_string()))?;
                
                Ok(PaginatedResult::new(items, total.0 as u64, page, per_page))
            }
        }
    };
}
基于真实业务，我在设计一个采用 Rust Workspace 的模块化后端架构，实现高内聚低耦合，并基于腾讯云VOD、阿里云VOD、支付宝、微信支付等官方文档进行对接的视频付费订阅网站，根据上方的配置库代码，和修改的最新公共库的错误类型，需要完成一下操作：
1.为了更好的处理错误，除配置库外，各个子库统一采用公共库的错误处理，所以现有数据库中的错误处理代码需要调整优化，使其更友好。
2.数据库连接池做全局加载，做简便获取方法，db库中的每个操作自动化获取数据库连接池，根据配置库的数据库配置进行完善
3.数据库库是参考java的jfianl框架做的，需要根据特征进行错误检查