use serde::{Deserialize, Serialize};
use validator::Validate;
use std::collections::HashMap;
use std::time::Duration;
use crate::ConfigLoader;
use crate::error::ConfigResult;

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
    
    /// 视频配置
    #[serde(default = "VideoConfig::default")]
    pub video: VideoConfig,
    
    /// 支付配置
    #[serde(default = "PaymentConfig::default")]
    pub payment: PaymentConfig,
    
    /// 限流配置
    #[serde(default = "RateLimitConfig::default")]
    pub rate_limit: RateLimitConfig,
    
    /// CORS配置
    #[serde(default = "CorsConfig::default")]
    pub cors: CorsConfig,
    
    /// 日志配置
    #[serde(default = "LoggingConfig::default")]
    pub logging: LoggingConfig,
    
    /// 监控配置
    #[serde(default = "TelemetryConfig::default")]
    pub telemetry: TelemetryConfig,
    
    /// 云服务配置
    #[serde(default = "CloudServiceConfig::default")]
    pub cloud_service: CloudServiceConfig,
    
    /// 存储配置
    #[serde(default = "StorageConfig::default")]
    pub storage: StorageConfig,
    
    /// 邮件配置
    #[serde(default = "EmailConfig::default")]
    pub email: EmailConfig,
    
    /// 短信配置
    #[serde(default = "SmsConfig::default")]
    pub sms: SmsConfig,
    
    /// CDN配置
    #[serde(default = "CdnConfig::default")]
    pub cdn: CdnConfig,
    
    /// 安全配置
    #[serde(default = "SecurityConfig::default")]
    pub security: SecurityConfig,
    
    /// 缓存配置
    #[serde(default = "CacheConfig::default")]
    pub cache: CacheConfig,
    
    /// 队列配置
    #[serde(default = "QueueConfig::default")]
    pub queue: QueueConfig,
    
    /// 任务配置
    #[serde(default = "TaskConfig::default")]
    pub task: TaskConfig,
    
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
    
    /// 工作线程数量
    #[serde(default = "default_worker_threads")]
    #[validate(range(min = 1, max = 64))]
    pub worker_threads: usize,
    
    /// 请求超时时间（秒）
    #[serde(default = "default_request_timeout")]
    #[validate(range(min = 1, max = 300))]
    pub request_timeout: u64,
    
    /// 关闭超时时间（秒）
    #[serde(default = "default_shutdown_timeout")]
     #[validate(range(min = 1, max = 300))]
    pub shutdown_timeout: u64,
    
    /// 最大请求体大小（MB）
    #[serde(default = "default_max_body_size")]
    #[validate(range(min = 1, max = 1000))]
    pub max_body_size: u64,
    
    /// 启用HTTPS
    #[serde(default = "default_enable_https")]
    pub enable_https: bool,
    
    /// HTTPS证书路径
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    
    /// HTTPS私钥路径
    #[serde(default)]
    pub tls_key_path: Option<String>,
    
    /// 启用HTTP/2
    #[serde(default = "default_enable_http2")]
    pub enable_http2: bool,
    
    /// 启用压缩
    #[serde(default = "default_enable_compression")]
    pub enable_compression: bool,
    
    /// 启用访问日志
    #[serde(default = "default_enable_access_log")]
    pub enable_access_log: bool,
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

/// JWT配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct JwtConfig {
    /// JWT密钥
    #[serde(default = "default_jwt_secret")]
    #[validate(length(min = 32))]
    pub secret: String,
    
    /// 访问令牌过期时间（小时）
    #[serde(default = "default_jwt_expiration")]
    #[validate(range(min = 1, max = 720))]
    pub expiration_hours: i64,
    
    /// 刷新令牌过期时间（天）
    #[serde(default = "default_refresh_expiration")]
    #[validate(range(min = 1, max = 365))]
    pub refresh_expiration_days: i64,
    
    /// 签发者
    #[serde(default = "default_jwt_issuer")]
    #[validate(length(min = 1))]
    pub issuer: String,
    
    /// 受众
    #[serde(default = "default_jwt_audience")]
    #[validate(length(min = 1))]
    pub audience: String,
    
    /// 算法
    #[serde(default = "default_jwt_algorithm")]
      #[validate(length(min = 1))]
    pub algorithm: String,
    
    /// 启用黑名单
    #[serde(default = "default_enable_jwt_blacklist")]
    pub enable_blacklist: bool,
    
    /// 黑名单TTL（秒）
    #[serde(default = "default_jwt_blacklist_ttl")]
     #[validate(range(min = 1))]
    pub blacklist_ttl: u64,
}

/// 加密配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct EncryptionConfig {
    /// 加密密钥（32字节，base64编码）
    #[serde(default = "default_encryption_key")]
    #[validate(length(min = 32))]
    pub key: String,
    
    /// 加密算法
    #[serde(default = "default_encryption_algorithm")]
    #[validate(length(min = 1))]
    pub algorithm: String,
    
    /// 初始化向量（IV）长度
    #[serde(default = "default_encryption_iv_length")]
     #[validate(range(min = 8, max = 16))]
    pub iv_length: usize,
    
    /// 认证标签长度
    #[serde(default = "default_encryption_tag_length")]
    #[validate(range(min = 12, max = 16))]
    pub tag_length: usize,
    
    /// 启用硬件加速
    #[serde(default = "default_enable_hardware_acceleration")]
    pub enable_hardware_acceleration: bool,
    
    /// 密钥轮换间隔（天）
    #[serde(default = "default_key_rotation_days")]
    #[validate(range(min = 1, max = 365))]
    pub key_rotation_days: u32,
}

/// 视频配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct VideoConfig {
    /// 最大文件大小（MB）
    #[serde(default = "default_max_file_size")]
    #[validate(range(min = 1, max = 10240))]
    pub max_file_size_mb: u64,
    
    /// 允许的视频格式
    #[serde(default = "default_allowed_formats")]
    pub allowed_formats: Vec<String>,
    
    /// 最大视频时长（秒）
    #[serde(default = "default_max_duration")]
    #[validate(range(min = 1, max = 36000))]
    pub max_duration_seconds: u32,
    
    /// 启用缩略图生成
    #[serde(default = "default_thumbnail_enabled")]
    pub thumbnail_enabled: bool,
    
    /// 缩略图尺寸
    #[serde(default = "default_thumbnail_size")]
    pub thumbnail_size: (u32, u32),
    
    /// 启用水印
    #[serde(default = "default_watermark_enabled")]
    pub watermark_enabled: bool,
    
    /// 水印图片路径
    #[serde(default)]
    pub watermark_path: Option<String>,
    
    /// 水印位置
    #[serde(default = "default_watermark_position")]
    pub watermark_position: String,
    
    /// 转码配置
    #[serde(default = "default_transcoding_profiles")]
    pub transcoding_profiles: Vec<TranscodingProfile>,
    
    /// 启用自适应码率
    #[serde(default = "default_enable_adaptive_bitrate")]
    pub enable_adaptive_bitrate: bool,
    
    /// 启用DRM加密
    #[serde(default = "default_enable_drm")]
    pub enable_drm: bool,
    
    /// DRM提供商
    #[serde(default = "default_drm_provider")]
    pub drm_provider: String,
    
    /// 启用内容审核
    #[serde(default = "default_enable_content_audit")]
    pub enable_content_audit: bool,
    
    /// 审核提供商
    #[serde(default = "default_audit_provider")]
    pub audit_provider: String,
}

/// 转码配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TranscodingProfile {
    /// 配置名称
    pub name: String,
    
    /// 宽度
    #[validate(range(min = 1, max = 7680))]
    pub width: u32,
    
    /// 高度
    #[validate(range(min = 1, max = 4320))]
    pub height: u32,
    
    /// 码率（kbps）
    #[validate(range(min = 100, max = 50000))]
    pub bitrate: u32,
    
    /// 视频编码器
    pub codec: String,
    
    /// 帧率
    #[validate(range(min = 1, max = 120))]
    pub framerate: u32,
    
    /// 关键帧间隔
    #[validate(range(min = 1, max = 300))]
    pub keyframe_interval: u32,
    
    /// 启用硬件加速
    pub hardware_acceleration: bool,
    
    /// 是否启用
    pub enabled: bool,
}

/// 支付配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PaymentConfig {
    /// 启用支付
    #[serde(default = "default_enable_payment")]
    pub enabled: bool,
    
    /// 默认货币
    #[serde(default = "default_currency")]
    pub default_currency: String,
    
    /// 平台手续费率（百分比）
    #[serde(default = "default_platform_fee_rate")]
    #[validate(range(min = 0.0, max = 50.0))]
    pub platform_fee_rate: f64,
    
    /// 最小提现金额
    #[serde(default = "default_min_withdrawal_amount")]
    pub min_withdrawal_amount: f64,
    
    /// 最大提现金额
    #[serde(default = "default_max_withdrawal_amount")]
    pub max_withdrawal_amount: f64,
    
    /// 提现处理时间（小时）
    #[serde(default = "default_withdrawal_processing_hours")]
    pub withdrawal_processing_hours: u32,
    
    /// 支付渠道配置
    #[serde(default = "default_payment_channels")]
    pub channels: HashMap<String, PaymentChannelConfig>,
    
    /// 启用沙箱模式
    #[serde(default = "default_enable_sandbox")]
    pub sandbox: bool,
    
    /// 支付回调URL
    #[serde(default = "default_payment_callback_url")]
    #[validate(url)]
    pub callback_url: String,
    
    /// 支付返回URL
    #[serde(default = "default_payment_return_url")]
    #[validate(url)]
    pub return_url: String,
}

/// 支付渠道配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PaymentChannelConfig {
    /// 是否启用
    pub enabled: bool,
    
    /// 应用ID
    pub app_id: String,
    
    /// 商户ID
    pub merchant_id: Option<String>,
    
    /// 私钥（加密存储）
    pub private_key: String,
    
    /// 公钥（加密存储）
    pub public_key: Option<String>,
    
    /// 回调URL
    #[validate(url)]
    pub notify_url: String,
    
    /// 沙箱模式
    pub sandbox: bool,
    
    /// 手续费率（百分比）
    #[validate(range(min = 0.0, max = 5.0))]
    pub fee_rate: f64,
    
    /// 支持的货币
    pub supported_currencies: Vec<String>,
    
    /// 额外配置
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

/// 限流配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RateLimitConfig {
    /// 启用限流
    #[serde(default = "default_enable_rate_limit")]
    pub enabled: bool,
    
    /// 全局请求限制（每分钟）
    #[serde(default = "default_global_rate_limit")]
    #[validate(range(min = 1, max = 10000))]
    pub global_limit: u32,
    
    /// IP请求限制（每分钟）
    #[serde(default = "default_ip_rate_limit")]
    #[validate(range(min = 1, max = 1000))]
    pub ip_limit: u32,
    
    /// 用户请求限制（每分钟）
    #[serde(default = "default_user_rate_limit")]
    #[validate(range(min = 1, max = 5000))]
    pub user_limit: u32,
    
    /// 上传请求限制（每分钟）
    #[serde(default = "default_upload_rate_limit")]
    #[validate(range(min = 1, max = 100))]
    pub upload_limit: u32,
    
    /// 验证码请求限制（每小时）
    #[serde(default = "default_captcha_rate_limit")]
    #[validate(range(min = 1, max = 50))]
    pub captcha_limit: u32,
    
    /// 限制窗口大小（秒）
    #[serde(default = "default_rate_limit_window")]
    pub window_seconds: u64,
    
    /// 启用滑动窗口
    #[serde(default = "default_enable_sliding_window")]
    pub sliding_window: bool,
}

/// CORS配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CorsConfig {
    /// 启用CORS
    #[serde(default = "default_enable_cors")]
    pub enabled: bool,
    
    /// 允许的来源
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,
    
    /// 允许的方法
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,
    
    /// 允许的请求头
    #[serde(default = "default_allowed_headers")]
    pub allowed_headers: Vec<String>,
    
    /// 允许的凭证
    #[serde(default = "default_allow_credentials")]
    pub allow_credentials: bool,
    
    /// 最大年龄（秒）
    #[serde(default = "default_max_age")]
    pub max_age: u64,
    
    /// 暴露的响应头
    #[serde(default = "default_expose_headers")]
    pub expose_headers: Vec<String>,
}

/// 日志配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LoggingConfig {
    /// 日志级别
    #[serde(default = "default_log_level")]
    pub level: String,
    
    /// 日志格式
    #[serde(default = "default_log_format")]
    pub format: String,
    
    /// 日志输出目录
    #[serde(default = "default_log_dir")]
    pub dir: String,
    
    /// 最大日志文件大小（MB）
    #[serde(default = "default_max_log_size")]
    pub max_file_size: u64,
    
    /// 最大保留文件数
    #[serde(default = "default_max_log_files")]
    pub max_files: u32,
    
    /// 启用控制台输出
    #[serde(default = "default_enable_console")]
    pub enable_console: bool,
    
    /// 启用文件输出
    #[serde(default = "default_enable_file")]
    pub enable_file: bool,
    
    /// 启用JSON格式
    #[serde(default = "default_enable_json")]
    pub enable_json: bool,
    
    /// 启用时间戳
    #[serde(default = "default_enable_timestamp")]
    pub enable_timestamp: bool,
    
    /// 启用线程ID
    #[serde(default = "default_enable_thread_id")]
    pub enable_thread_id: bool,
    
    /// 启用追踪ID
    #[serde(default = "default_enable_trace_id")]
    pub enable_trace_id: bool,
}

/// 监控配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TelemetryConfig {
    /// 启用监控
    #[serde(default = "default_enable_telemetry")]
    pub enabled: bool,
    
    /// 监控服务提供商
    #[serde(default = "default_telemetry_provider")]
    pub provider: String,
    
    /// 端点URL
    #[serde(default = "default_telemetry_endpoint")]
    #[validate(url)]
    pub endpoint: String,
    
    /// 采样率（0-1）
    #[serde(default = "default_sampling_rate")]
    #[validate(range(min = 0.0, max = 1.0))]
    pub sampling_rate: f64,
    
    /// 启用指标收集
    #[serde(default = "default_enable_metrics")]
    pub enable_metrics: bool,
    
    /// 启用追踪
    #[serde(default = "default_enable_tracing")]
    pub enable_tracing: bool,
    
    /// 启用日志记录
    #[serde(default = "default_enable_logs")]
    pub enable_logs: bool,
    
    /// 服务名称
    #[serde(default = "default_service_name")]
    pub service_name: String,
    
    /// 服务版本
    #[serde(default = "default_service_version")]
    pub service_version: String,
    
    /// 部署环境
    #[serde(default = "default_deployment_env")]
    pub deployment_env: String,
}

/// 云服务配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CloudServiceConfig {
    /// 默认云服务提供商
    #[serde(default = "default_cloud_provider")]
    pub default_provider: String,
    
    /// 腾讯云配置
    #[serde(default)]
    pub tencent: TencentCloudConfig,
    
    /// 阿里云配置
    #[serde(default)]
    pub aliyun: AliyunCloudConfig,
    
    /// AWS配置
    #[serde(default)]
    pub aws: AwsCloudConfig,
    
    /// 华为云配置
    #[serde(default)]
    pub huawei: HuaweiCloudConfig,
}

/// 腾讯云配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TencentCloudConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// SecretId
    #[serde(default)]
    pub secret_id: Option<String>,
    
    /// SecretKey（加密存储）
    #[serde(default)]
    pub secret_key: Option<String>,
    
    /// 区域
    #[serde(default = "default_tencent_region")]
    pub region: String,
    
    /// VOD配置
    #[serde(default)]
    pub vod: TencentVodConfig,
    
    /// COS配置
    #[serde(default)]
    pub cos: TencentCosConfig,
}

/// 腾讯云VOD配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TencentVodConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 子应用ID
    #[serde(default)]
    pub sub_app_id: Option<u64>,
    
    /// 存储区域
    #[serde(default = "default_tencent_vod_storage_region")]
    pub storage_region: String,
    
    /// 转码模板
    #[serde(default = "default_tencent_vod_transcode_template")]
    pub transcode_template: String,
    
    /// 水印模板ID
    #[serde(default)]
    pub watermark_template_id: Option<String>,
    
    /// 启用DRM
    #[serde(default = "default_enable_drm")]
    pub enable_drm: bool,
}

/// 腾讯云COS配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TencentCosConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 存储桶名称
    #[serde(default)]
    pub bucket: Option<String>,
    
    /// 区域
    #[serde(default = "default_tencent_cos_region")]
    pub region: String,
    
    /// 启用CDN
    #[serde(default = "default_enable_cdn")]
    pub enable_cdn: bool,
    
    /// CDN域名
    #[serde(default)]
    pub cdn_domain: Option<String>,
}

/// 阿里云配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliyunCloudConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// AccessKeyId
    #[serde(default)]
    pub access_key_id: Option<String>,
    
    /// AccessKeySecret（加密存储）
    #[serde(default)]
    pub access_key_secret: Option<String>,
    
    /// 区域
    #[serde(default = "default_aliyun_region")]
    pub region: String,
    
    /// VOD配置
    #[serde(default)]
    pub vod: AliyunVodConfig,
    
    /// OSS配置
    #[serde(default)]
    pub oss: AliyunOssConfig,
}

/// 阿里云VOD配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliyunVodConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 存储区域
    #[serde(default = "default_aliyun_vod_storage_region")]
    pub storage_region: String,
    
    /// 转码模板组ID
    #[serde(default)]
    pub transcode_template_group_id: Option<String>,
    
    /// 水印模板ID
    #[serde(default)]
    pub watermark_template_id: Option<String>,
    
    /// 启用DRM
    #[serde(default = "default_enable_drm")]
    pub enable_drm: bool,
}

/// 阿里云OSS配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliyunOssConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 存储桶名称
    #[serde(default)]
    pub bucket: Option<String>,
    
    /// 区域
    #[serde(default = "default_aliyun_oss_region")]
    pub region: String,
    
    /// 启用CDN
    #[serde(default = "default_enable_cdn")]
    pub enable_cdn: bool,
    
    /// CDN域名
    #[serde(default)]
    pub cdn_domain: Option<String>,
}

/// AWS配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCloudConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// AccessKeyId
    #[serde(default)]
    pub access_key_id: Option<String>,
    
    /// SecretAccessKey（加密存储）
    #[serde(default)]
    pub secret_access_key: Option<String>,
    
    /// 区域
    #[serde(default = "default_aws_region")]
    pub region: String,
    
    /// S3配置
    #[serde(default)]
    pub s3: AwsS3Config,
}

/// AWS S3配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsS3Config {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 存储桶名称
    #[serde(default)]
    pub bucket: Option<String>,
    
    /// 启用CDN
    #[serde(default = "default_enable_cdn")]
    pub enable_cdn: bool,
    
    /// CloudFront域名
    #[serde(default)]
    pub cloudfront_domain: Option<String>,
}

/// 华为云配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuaweiCloudConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// AccessKeyId
    #[serde(default)]
    pub access_key_id: Option<String>,
    
    /// SecretAccessKey（加密存储）
    #[serde(default)]
    pub secret_access_key: Option<String>,
    
    /// 区域
    #[serde(default = "default_huawei_region")]
    pub region: String,
    
    /// OBS配置
    #[serde(default)]
    pub obs: HuaweiObsConfig,
}

/// 华为云OBS配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuaweiObsConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 存储桶名称
    #[serde(default)]
    pub bucket: Option<String>,
    
    /// 区域
    #[serde(default = "default_huawei_obs_region")]
    pub region: String,
    
    /// 启用CDN
    #[serde(default = "default_enable_cdn")]
    pub enable_cdn: bool,
    
    /// CDN域名
    #[serde(default)]
    pub cdn_domain: Option<String>,
}

/// 存储配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct StorageConfig {
    /// 默认存储提供商
    #[serde(default = "default_storage_provider")]
    pub default_provider: String,
    
    /// 本地存储配置
    #[serde(default)]
    pub local: LocalStorageConfig,
    
    /// S3兼容存储配置
    #[serde(default)]
    pub s3: S3StorageConfig,
    
    /// 启用多存储提供商
    #[serde(default = "default_enable_multi_storage")]
    pub enable_multi_storage: bool,
    
    /// 存储策略
    #[serde(default = "default_storage_strategy")]
    pub strategy: String,
}

/// 本地存储配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LocalStorageConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 存储目录
    #[serde(default = "default_local_storage_dir")]
    pub dir: String,
    
    /// 最大存储空间（GB）
    #[serde(default = "default_local_max_storage")]
    pub max_storage_gb: u64,
    
    /// 启用符号链接
    #[serde(default = "default_enable_symlink")]
    pub enable_symlink: bool,
    
    /// 文件权限
    #[serde(default = "default_file_permissions")]
    pub file_permissions: String,
}

/// S3兼容存储配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct S3StorageConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 端点URL
    #[serde(default = "default_s3_endpoint")]
    #[validate(url)]
    pub endpoint: String,
    
    /// 区域
    #[serde(default = "default_s3_region")]
    pub region: String,
    
    /// 存储桶名称
    #[serde(default)]
    pub bucket: Option<String>,
    
    /// AccessKeyId
    #[serde(default)]
    pub access_key_id: Option<String>,
    
    /// SecretAccessKey（加密存储）
    #[serde(default)]
    pub secret_access_key: Option<String>,
    
    /// 启用SSL
    #[serde(default = "default_enable_ssl")]
    pub enable_ssl: bool,
    
    /// 启用路径风格
    #[serde(default = "default_enable_path_style")]
    pub path_style: bool,
}

/// 邮件配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct EmailConfig {
    /// 启用邮件服务
    #[serde(default = "default_enable_email")]
    pub enabled: bool,
    
    /// SMTP服务器
    #[serde(default = "default_smtp_server")]
    pub smtp_server: String,
    
    /// SMTP端口
    #[serde(default = "default_smtp_port")]
    #[validate(range(min = 1, max = 65535))]
    pub smtp_port: u16,
    
    /// 用户名
    #[serde(default)]
    pub username: Option<String>,
    
    /// 密码（加密存储）
    #[serde(default)]
    pub password: Option<String>,
    
    /// 发件人邮箱
    #[serde(default = "default_sender_email")]
    #[validate(email)]
    pub sender_email: String,
    
    /// 发件人名称
    #[serde(default = "default_sender_name")]
    pub sender_name: String,
    
    /// 启用TLS
    #[serde(default = "default_enable_tls")]
    pub enable_tls: bool,
    
    /// 启用STARTTLS
    #[serde(default = "default_enable_starttls")]
    pub enable_starttls: bool,
    
    /// 连接超时时间（秒）
    #[serde(default = "default_email_connect_timeout")]
    pub connect_timeout: u64,
    
    /// 命令超时时间（秒）
    #[serde(default = "default_email_command_timeout")]
    pub command_timeout: u64,
}

/// 短信配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SmsConfig {
    /// 启用短信服务
    #[serde(default = "default_enable_sms")]
    pub enabled: bool,
    
    /// 短信提供商
    #[serde(default = "default_sms_provider")]
    pub provider: String,
    
    /// AccessKeyId
    #[serde(default)]
    pub access_key_id: Option<String>,
    
    /// AccessKeySecret（加密存储）
    #[serde(default)]
    pub access_key_secret: Option<String>,
    
    /// 短信签名
    #[serde(default)]
    pub sign_name: Option<String>,
    
    /// 短信模板ID
    #[serde(default)]
    pub template_id: Option<String>,
    
    /// 短信发送频率限制（秒）
    #[serde(default = "default_sms_rate_limit")]
    pub rate_limit_seconds: u64,
    
    /// 短信验证码有效期（秒）
    #[serde(default = "default_sms_code_expiry")]
    pub code_expiry_seconds: u64,
    
    /// 启用国际短信
    #[serde(default = "default_enable_international_sms")]
    pub enable_international: bool,
    
    /// 默认国家代码
    #[serde(default = "default_country_code")]
    pub default_country_code: String,
}

/// CDN配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CdnConfig {
    /// 启用CDN
    #[serde(default = "default_enable_cdn")]
    pub enabled: bool,
    
    /// CDN提供商
    #[serde(default = "default_cdn_provider")]
    pub provider: String,
    
    /// CDN域名
    #[serde(default)]
    pub domain: Option<String>,
    
    /// 启用HTTPS
    #[serde(default = "default_enable_https")]
    pub enable_https: bool,
    
    /// 启用HTTP/2
    #[serde(default = "default_enable_http2")]
    pub enable_http2: bool,
    
    /// 缓存策略
    #[serde(default = "default_cdn_cache_policy")]
    pub cache_policy: String,
    
    /// 缓存时间（秒）
    #[serde(default = "default_cdn_cache_ttl")]
    pub cache_ttl: u64,
    
    /// 启用Gzip压缩
    #[serde(default = "default_enable_gzip")]
    pub enable_gzip: bool,
    
    /// 启用Brotli压缩
    #[serde(default = "default_enable_brotli")]
    pub enable_brotli: bool,
    
    /// 启用防盗链
    #[serde(default = "default_enable_referer")]
    pub enable_referer: bool,
    
    /// 允许的引用来源
    #[serde(default)]
    pub allowed_referers: Vec<String>,
}

/// 安全配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SecurityConfig {
    /// 启用安全头
    #[serde(default = "default_enable_security_headers")]
    pub enable_headers: bool,
    
    /// 启用CSP
    #[serde(default = "default_enable_csp")]
    pub enable_csp: bool,
    
    /// CSP策略
    #[serde(default = "default_csp_policy")]
    pub csp_policy: String,
    
    /// 启用HSTS
    #[serde(default = "default_enable_hsts")]
    pub enable_hsts: bool,
    
    /// HSTS最大年龄（秒）
    #[serde(default = "default_hsts_max_age")]
    pub hsts_max_age: u64,
    
    /// 启用XSS保护
    #[serde(default = "default_enable_xss_protection")]
    pub enable_xss_protection: bool,
    
    /// 启用点击劫持保护
    #[serde(default = "default_enable_clickjacking_protection")]
    pub enable_clickjacking_protection: bool,
    
    /// 启用MIME嗅探保护
    #[serde(default = "default_enable_mime_sniffing_protection")]
    pub enable_mime_sniffing_protection: bool,
    
    /// 启用Referrer策略
    #[serde(default = "default_enable_referrer_policy")]
    pub enable_referrer_policy: bool,
    
    /// Referrer策略
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: String,
    
    /// 启用证书固定
    #[serde(default = "default_enable_certificate_pinning")]
    pub enable_certificate_pinning: bool,
    
    /// 证书公钥哈希列表
    #[serde(default)]
    pub certificate_pins: Vec<String>,
    
    /// 启用请求签名
    #[serde(default = "default_enable_request_signing")]
    pub enable_request_signing: bool,
    
    /// 签名密钥（加密存储）
    #[serde(default)]
    pub signing_key: Option<String>,
    
    /// 签名算法
    #[serde(default = "default_signing_algorithm")]
    pub signing_algorithm: String,
}

/// 缓存配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CacheConfig {
    /// 启用缓存
    #[serde(default = "default_enable_cache")]
    pub enabled: bool,
    
    /// 默认缓存时间（秒）
    #[serde(default = "default_cache_ttl")]
    pub default_ttl: u64,
    
    /// 最大缓存大小（MB）
    #[serde(default = "default_max_cache_size")]
    pub max_size_mb: u64,
    
    /// 缓存清理间隔（秒）
    #[serde(default = "default_cache_cleanup_interval")]
    pub cleanup_interval: u64,
    
    /// 缓存策略
    #[serde(default = "default_cache_strategy")]
    pub strategy: String,
    
    /// 启用内存缓存
    #[serde(default = "default_enable_memory_cache")]
    pub enable_memory: bool,
    
    /// 启用Redis缓存
    #[serde(default = "default_enable_redis_cache")]
    pub enable_redis: bool,
    
    /// 启用分布式缓存
    #[serde(default = "default_enable_distributed_cache")]
    pub enable_distributed: bool,
}

/// 队列配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct QueueConfig {
    /// 启用队列
    #[serde(default = "default_enable_queue")]
    pub enabled: bool,
    
    /// 队列提供商
    #[serde(default = "default_queue_provider")]
    pub provider: String,
    
    /// Redis队列配置
    #[serde(default)]
    pub redis: RedisQueueConfig,
    
    /// RabbitMQ队列配置
    #[serde(default)]
    pub rabbitmq: RabbitMqQueueConfig,
    
    /// SQS队列配置
    #[serde(default)]
    pub sqs: SqsQueueConfig,
    
    /// 默认队列名称
    #[serde(default = "default_queue_name")]
    pub default_queue: String,
    
    /// 重试次数
    #[serde(default = "default_queue_retries")]
    pub retries: u32,
    
    /// 重试延迟（秒）
    #[serde(default = "default_queue_retry_delay")]
    pub retry_delay: u64,
    
    /// 最大并发工作者
    #[serde(default = "default_max_workers")]
    pub max_workers: u32,
    
    /// 工作者空闲超时（秒）
    #[serde(default = "default_worker_idle_timeout")]
    pub worker_idle_timeout: u64,
}

/// Redis队列配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisQueueConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 连接URL
    #[serde(default = "default_redis_queue_url")]
    pub url: String,
    
    /// 队列名称前缀
    #[serde(default = "default_queue_prefix")]
    pub prefix: String,
    
    /// 队列数量
    #[serde(default = "default_queue_count")]
    pub queue_count: u32,
}

/// RabbitMQ队列配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMqQueueConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 连接URL
    #[serde(default = "default_rabbitmq_url")]
    pub url: String,
    
    /// 交换机名称
    #[serde(default = "default_exchange_name")]
    pub exchange: String,
    
    /// 交换机类型
    #[serde(default = "default_exchange_type")]
    pub exchange_type: String,
    
    /// 队列名称
    #[serde(default = "default_queue_name")]
    pub queue: String,
    
    /// 路由键
    #[serde(default = "default_routing_key")]
    pub routing_key: String,
}

/// SQS队列配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqsQueueConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 队列URL
    #[serde(default)]
    pub queue_url: Option<String>,
    
    /// 区域
    #[serde(default = "default_aws_region")]
    pub region: String,
    
    /// AccessKeyId
    #[serde(default)]
    pub access_key_id: Option<String>,
    
    /// SecretAccessKey（加密存储）
    #[serde(default)]
    pub secret_access_key: Option<String>,
}

/// 任务配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TaskConfig {
    /// 启用定时任务
    #[serde(default = "default_enable_tasks")]
    pub enabled: bool,
    
    /// 任务调度器
    #[serde(default = "default_task_scheduler")]
    pub scheduler: String,
    
    /// 数据库清理任务配置
    #[serde(default)]
    pub database_cleanup: DatabaseCleanupTaskConfig,
    
    /// 缓存清理任务配置
    #[serde(default)]
    pub cache_cleanup: CacheCleanupTaskConfig,
    
    /// 邮件发送任务配置
    #[serde(default)]
    pub email_send: EmailSendTaskConfig,
    
    /// 视频转码任务配置
    #[serde(default)]
    pub video_transcode: VideoTranscodeTaskConfig,
    
    /// 统计任务配置
    #[serde(default)]
    pub statistics: StatisticsTaskConfig,
    
    /// 备份任务配置
    #[serde(default)]
    pub backup: BackupTaskConfig,
}

/// 数据库清理任务配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DatabaseCleanupTaskConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 执行周期（秒）
    #[serde(default = "default_database_cleanup_interval")]
    pub interval: u64,
    
    /// 保留天数
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    
    /// 清理的表
    #[serde(default)]
    pub tables: Vec<String>,
    
    /// 批次大小
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
}

/// 缓存清理任务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheCleanupTaskConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 执行周期（秒）
    #[serde(default = "default_cache_cleanup_interval")]
    pub interval: u64,
    
    /// 清理模式
    #[serde(default = "default_cleanup_mode")]
    pub mode: String,
    
    /// 清理比例（0-1）
    #[serde(default = "default_cleanup_ratio")]
    pub ratio: f64,
}

/// 邮件发送任务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSendTaskConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 执行周期（秒）
    #[serde(default = "default_email_send_interval")]
    pub interval: u64,
    
    /// 批次大小
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
    
    /// 重试次数
    #[serde(default = "default_retry_count")]
    pub retry_count: u32,
}

/// 视频转码任务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoTranscodeTaskConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 执行周期（秒）
    #[serde(default = "default_transcode_interval")]
    pub interval: u64,
    
    /// 最大并发任务数
    #[serde(default = "default_max_concurrent_tasks")]
    pub max_concurrent: u32,
    
    /// 超时时间（秒）
    #[serde(default = "default_transcode_timeout")]
    pub timeout: u64,
    
    /// 重试次数
    #[serde(default = "default_retry_count")]
    pub retry_count: u32,
}

/// 统计任务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsTaskConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 执行周期（秒）
    #[serde(default = "default_statistics_interval")]
    pub interval: u64,
    
    /// 统计项目
    #[serde(default)]
    pub metrics: Vec<String>,
    
    /// 保留天数
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

/// 备份任务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupTaskConfig {
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    
    /// 执行周期（秒）
    #[serde(default = "default_backup_interval")]
    pub interval: u64,
    
    /// 备份目录
    #[serde(default = "default_backup_dir")]
    pub backup_dir: String,
    
    /// 保留天数
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    
    /// 压缩算法
    #[serde(default = "default_compression_algorithm")]
    pub compression: String,
    
    /// 加密备份
    #[serde(default = "default_encrypt_backup")]
    pub encrypt: bool,
}

/// 特性开关配置
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct FeatureConfig {
    /// 启用用户注册
    #[serde(default = "default_enable_registration")]
    pub enable_registration: bool,
    
    /// 启用邮箱验证
    #[serde(default = "default_enable_email_verification")]
    pub enable_email_verification: bool,
    
    /// 启用手机验证
    #[serde(default = "default_enable_phone_verification")]
    pub enable_phone_verification: bool,
    
    /// 启用两步验证
    #[serde(default = "default_enable_two_factor")]
    pub enable_two_factor: bool,
    
    /// 启用社交登录
    #[serde(default = "default_enable_social_login")]
    pub enable_social_login: bool,
    
    /// 启用API文档
    #[serde(default = "default_enable_api_docs")]
    pub enable_api_docs: bool,
    
    /// 启用管理面板
    #[serde(default = "default_enable_admin_panel")]
    pub enable_admin_panel: bool,
    
    /// 启用实时通知
    #[serde(default = "default_enable_realtime_notifications")]
    pub enable_realtime_notifications: bool,
    
    /// 启用WebSocket
    #[serde(default = "default_enable_websocket")]
    pub enable_websocket: bool,
    
    /// 启用GraphQL
    #[serde(default = "default_enable_graphql")]
    pub enable_graphql: bool,
    
    /// 启用搜索功能
    #[serde(default = "default_enable_search")]
    pub enable_search: bool,
    
    /// 启用推荐系统
    #[serde(default = "default_enable_recommendations")]
    pub enable_recommendations: bool,
    
    /// 启用分析功能
    #[serde(default = "default_enable_analytics")]
    pub enable_analytics: bool,
    
    /// 启用A/B测试
    #[serde(default = "default_enable_ab_testing")]
    pub enable_ab_testing: bool,
    
    /// 启用实验功能
    #[serde(default = "default_enable_experimental_features")]
    pub enable_experimental: bool,
}

// 默认值函数
fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 3000 }
fn default_worker_threads() -> usize { num_cpus::get() }
fn default_request_timeout() -> u64 { 30 }
fn default_shutdown_timeout() -> u64 { 30 }
fn default_max_body_size() -> u64 { 10 } // 10MB
fn default_enable_https() -> bool { false }
fn default_enable_http2() -> bool { true }
fn default_enable_compression() -> bool { true }
fn default_enable_access_log() -> bool { true }

fn default_database_url() -> String { "postgres://postgres:password@localhost:5432/luser".to_string() }
fn default_max_connections() -> u32 { 20 }
fn default_min_connections() -> u32 { 5 }
fn default_connection_timeout() -> u64 { 30 }
fn default_idle_timeout() -> u64 { 600 }
fn default_max_lifetime() -> u64 { 1800 }
fn default_enable_health_check() -> bool { true }
fn default_enable_ssl() -> bool { false }
fn default_enable_path_style() ->bool { false }
fn default_pool_name() -> String { "luser-pool".to_string() }

fn default_redis_url() -> String { "redis://localhost:6379".to_string() }
fn default_redis_pool_size() -> usize { 10 }
fn default_redis_ttl() -> u64 { 3600 }
fn default_redis_connect_timeout() -> u64 { 10 }
fn default_redis_command_timeout() -> u64 { 30 }
fn default_redis_enable_tls() -> bool { false }
fn default_redis_cluster_mode() -> bool { false }
fn default_redis_sentinel_mode() -> bool { false }
fn default_redis_database() -> u8 { 0 }

fn default_jwt_secret() -> String { "your-super-secret-jwt-key-change-in-production".to_string() }
fn default_jwt_expiration() -> i64 { 24 }
fn default_refresh_expiration() -> i64 { 30 }
fn default_jwt_issuer() -> String { "luser-platform".to_string() }
fn default_jwt_audience() -> String { "luser-users".to_string() }
fn default_jwt_algorithm() -> String { "HS256".to_string() }
fn default_enable_jwt_blacklist() -> bool { true }
fn default_jwt_blacklist_ttl() -> u64 { 86400 }

fn default_encryption_key() -> String { base64::encode(vec![0u8; 32]) }
fn default_encryption_algorithm() -> String { "AES-GCM".to_string() }
fn default_encryption_iv_length() -> usize { 12 }
fn default_encryption_tag_length() -> usize { 16 }
fn default_enable_hardware_acceleration() -> bool { true }
fn default_key_rotation_days() -> u32 { 90 }

fn default_max_file_size() -> u64 { 2048 }
fn default_allowed_formats() -> Vec<String> { vec!["mp4".to_string(), "mov".to_string(), "avi".to_string(), "mkv".to_string()] }
fn default_max_duration() -> u32 { 7200 }
fn default_thumbnail_enabled() -> bool { true }
fn default_thumbnail_size() -> (u32, u32) { (320, 180) }
fn default_watermark_enabled() -> bool { false }
fn default_watermark_position() -> String { "bottom-right".to_string() }
fn default_transcoding_profiles() -> Vec<TranscodingProfile> {
    vec![
        TranscodingProfile {
            name: "360p".to_string(),
            width: 640,
            height: 360,
            bitrate: 800,
            codec: "h264".to_string(),
            framerate: 30,
            keyframe_interval: 60,
            hardware_acceleration: true,
            enabled: true,
        },
        TranscodingProfile {
            name: "720p".to_string(),
            width: 1280,
            height: 720,
            bitrate: 2500,
            codec: "h264".to_string(),
            framerate: 30,
            keyframe_interval: 60,
            hardware_acceleration: true,
            enabled: true,
        },
        TranscodingProfile {
            name: "1080p".to_string(),
            width: 1920,
            height: 1080,
            bitrate: 5000,
            codec: "h264".to_string(),
            framerate: 30,
            keyframe_interval: 60,
            hardware_acceleration: true,
            enabled: true,
        },
    ]
}
fn default_enable_adaptive_bitrate() -> bool { true }
fn default_enable_drm() -> bool { false }
fn default_drm_provider() -> String { "widevine".to_string() }
fn default_enable_content_audit() -> bool { true }
fn default_audit_provider() -> String { "aliyun".to_string() }

fn default_enable_payment() -> bool { true }
fn default_currency() -> String { "CNY".to_string() }
fn default_platform_fee_rate() -> f64 { 0.2 }
fn default_min_withdrawal_amount() -> f64 { 100.0 }
fn default_max_withdrawal_amount() -> f64 { 50000.0 }
fn default_withdrawal_processing_hours() -> u32 { 24 }
fn default_payment_channels() -> HashMap<String, PaymentChannelConfig> { HashMap::new() }
fn default_enable_sandbox() -> bool { false }
fn default_payment_callback_url() -> String { "https://api.luser.com/payment/callback".to_string() }
fn default_payment_return_url() -> String { "https://luser.com/payment/return".to_string() }

fn default_enable_rate_limit() -> bool { true }
fn default_global_rate_limit() -> u32 { 1000 }
fn default_ip_rate_limit() -> u32 { 100 }
fn default_user_rate_limit() -> u32 { 500 }
fn default_upload_rate_limit() -> u32 { 10 }
fn default_captcha_rate_limit() -> u32 { 10 }
fn default_rate_limit_window() -> u64 { 60 }
fn default_enable_sliding_window() -> bool { true }

fn default_enable_cors() -> bool { true }
fn default_allowed_origins() -> Vec<String> { vec!["*".to_string()] }
fn default_allowed_methods() -> Vec<String> { vec!["GET".to_string(), "POST".to_string(), "PUT".to_string(), "DELETE".to_string(), "OPTIONS".to_string()] }
fn default_allowed_headers() -> Vec<String> { vec!["*".to_string()] }
fn default_allow_credentials() -> bool { false }
fn default_max_age() -> u64 { 86400 }
fn default_expose_headers() -> Vec<String> { vec![] }

fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "text".to_string() }
fn default_log_dir() -> String { "./logs".to_string() }
fn default_max_log_size() -> u64 { 100 }
fn default_max_log_files() -> u32 { 10 }
fn default_enable_console() -> bool { true }
fn default_enable_file() -> bool { true }
fn default_enable_json() -> bool { false }
fn default_enable_timestamp() -> bool { true }
fn default_enable_thread_id() -> bool { false }
fn default_enable_trace_id() -> bool { true }

fn default_enable_telemetry() -> bool { true }
fn default_telemetry_provider() -> String { "opentelemetry".to_string() }
fn default_telemetry_endpoint() -> String { "http://localhost:4317".to_string() }
fn default_sampling_rate() -> f64 { 0.1 }
fn default_enable_metrics() -> bool { true }
fn default_enable_tracing() -> bool { true }
fn default_enable_logs() -> bool { true }
fn default_service_name() -> String { "luser-api".to_string() }
fn default_service_version() -> String { env!("CARGO_PKG_VERSION").to_string() }
fn default_deployment_env() -> String { "development".to_string() }

fn default_cloud_provider() -> String { "tencent".to_string() }
fn default_enabled() -> bool { false }
fn default_tencent_region() -> String { "ap-guangzhou".to_string() }
fn default_tencent_vod_storage_region() -> String { "ap-guangzhou".to_string() }
fn default_tencent_vod_transcode_template() -> String { "LongVideoPreset".to_string() }
fn default_tencent_cos_region() -> String { "ap-guangzhou".to_string() }
fn default_aliyun_region() -> String { "cn-shanghai".to_string() }
fn default_aliyun_vod_storage_region() -> String { "cn-shanghai".to_string() }
fn default_aliyun_oss_region() -> String { "cn-shanghai".to_string() }
fn default_aws_region() -> String { "us-east-1".to_string() }
fn default_huawei_region() -> String { "cn-north-1".to_string() }
fn default_huawei_obs_region() -> String { "cn-north-1".to_string() }

fn default_storage_provider() -> String { "local".to_string() }
fn default_local_storage_dir() -> String { "./storage".to_string() }
fn default_local_max_storage() -> u64 { 100 }
fn default_enable_symlink() -> bool { false }
fn default_file_permissions() -> String { "0644".to_string() }
fn default_s3_endpoint() -> String { "http://localhost:9000".to_string() }
fn default_s3_region() -> String { "us-east-1".to_string() }
fn default_enable_multi_storage() -> bool { false }
fn default_storage_strategy() -> String { "primary".to_string() }

fn default_enable_email() -> bool { false }
fn default_smtp_server() -> String { "smtp.gmail.com".to_string() }
fn default_smtp_port() -> u16 { 587 }
fn default_sender_email() -> String { "noreply@example.com".to_string() }
fn default_sender_name() -> String { "Luser Platform".to_string() }
fn default_enable_tls() -> bool { false }
fn default_enable_starttls() -> bool { false }
fn default_email_connect_timeout() -> u64 { 30 }
fn default_email_command_timeout() -> u64 { 60 }

fn default_enable_sms() -> bool { false }
fn default_sms_provider() -> String { "aliyun".to_string() }
fn default_sms_rate_limit() -> u64 { 60 }
fn default_sms_code_expiry() -> u64 { 300 }
fn default_enable_international_sms() -> bool { false }
fn default_country_code() -> String { "+86".to_string() }

fn default_enable_cdn() -> bool { false }
fn default_cdn_provider() -> String { "cloudflare".to_string() }
fn default_cdn_cache_policy() -> String { "public, max-age=31536000".to_string() }
fn default_cdn_cache_ttl() -> u64 { 31536000 }
fn default_enable_gzip() -> bool { true }
fn default_enable_brotli() -> bool { true }
fn default_enable_referer() -> bool { false }

fn default_enable_security_headers() -> bool { true }
fn default_enable_csp() -> bool { true }
fn default_csp_policy() -> String { "default-src 'self'".to_string() }
fn default_enable_hsts() -> bool { true }
fn default_hsts_max_age() -> u64 { 31536000 }
fn default_enable_xss_protection() -> bool { true }
fn default_enable_clickjacking_protection() -> bool { true }
fn default_enable_mime_sniffing_protection() -> bool { true }
fn default_enable_referrer_policy() -> bool { true }
fn default_referrer_policy() -> String { "strict-origin-when-cross-origin".to_string() }
fn default_enable_certificate_pinning() -> bool { false }
fn default_enable_request_signing() -> bool { false }
fn default_signing_algorithm() -> String { "HMAC-SHA256".to_string() }

fn default_enable_cache() -> bool { true }
fn default_cache_ttl() -> u64 { 3600 }
fn default_max_cache_size() -> u64 { 100 }
fn default_cache_cleanup_interval() -> u64 { 3600 }
fn default_cache_strategy() -> String { "lru".to_string() }
fn default_enable_memory_cache() -> bool { true }
fn default_enable_redis_cache() -> bool { true }
fn default_enable_distributed_cache() -> bool { false }

fn default_enable_queue() -> bool { false }
fn default_queue_provider() -> String { "redis".to_string() }
fn default_redis_queue_url() -> String { "redis://localhost:6379".to_string() }
fn default_queue_prefix() -> String { "luser:queue".to_string() }
fn default_queue_count() -> u32 { 1 }
fn default_rabbitmq_url() -> String { "amqp://guest:guest@localhost:5672".to_string() }
fn default_exchange_name() -> String { "luser-exchange".to_string() }
fn default_exchange_type() -> String { "direct".to_string() }
fn default_queue_name() -> String { "luser-queue".to_string() }
fn default_routing_key() -> String { "luser-task".to_string() }
fn default_queue_retries() -> u32 { 3 }
fn default_queue_retry_delay() -> u64 { 5 }
fn default_max_workers() -> u32 { 10 }
fn default_worker_idle_timeout() -> u64 { 300 }

fn default_enable_tasks() -> bool { true }
fn default_task_scheduler() -> String { "database".to_string() }
fn default_database_cleanup_interval() -> u64 { 86400 }
fn default_retention_days() -> u32 { 30 }
fn default_batch_size() -> u32 { 1000 }
fn default_cleanup_mode() -> String { "lru".to_string() }
fn default_cleanup_ratio() -> f64 { 0.2 }
fn default_email_send_interval() -> u64 { 60 }
fn default_retry_count() -> u32 { 3 }
fn default_transcode_interval() -> u64 { 60 }
fn default_max_concurrent_tasks() -> u32 { 5 }
fn default_transcode_timeout() -> u64 { 3600 }
fn default_statistics_interval() -> u64 { 3600 }
fn default_backup_interval() -> u64 { 86400 }
fn default_backup_dir() -> String { "./backups".to_string() }
fn default_compression_algorithm() -> String { "gzip".to_string() }
fn default_encrypt_backup() -> bool { true }

fn default_enable_registration() -> bool { true }
fn default_enable_email_verification() -> bool { true }
fn default_enable_phone_verification() -> bool { false }
fn default_enable_two_factor() -> bool { false }
fn default_enable_social_login() -> bool { false }
fn default_enable_api_docs() -> bool { true }
fn default_enable_admin_panel() -> bool { true }
fn default_enable_realtime_notifications() -> bool { true }
fn default_enable_websocket() -> bool { true }
fn default_enable_graphql() -> bool { false }
fn default_enable_search() -> bool { true }
fn default_enable_recommendations() -> bool { true }
fn default_enable_analytics() -> bool { true }
fn default_enable_ab_testing() -> bool { false }
fn default_enable_experimental_features() -> bool { false }

// 实现默认值
impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            redis: RedisConfig::default(),
            jwt: JwtConfig::default(),
            encryption: EncryptionConfig::default(),
            video: VideoConfig::default(),
            payment: PaymentConfig::default(),
            rate_limit: RateLimitConfig::default(),
            cors: CorsConfig::default(),
            logging: LoggingConfig::default(),
            telemetry: TelemetryConfig::default(),
            cloud_service: CloudServiceConfig::default(),
            storage: StorageConfig::default(),
            email: EmailConfig::default(),
            sms: SmsConfig::default(),
            cdn: CdnConfig::default(),
            security: SecurityConfig::default(),
            cache: CacheConfig::default(),
            queue: QueueConfig::default(),
            task: TaskConfig::default(),
            features: FeatureConfig::default(),
            extensions: HashMap::new(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            worker_threads: default_worker_threads(),
            request_timeout: default_request_timeout(),
            shutdown_timeout: default_shutdown_timeout(),
            max_body_size: default_max_body_size(),
            enable_https: default_enable_https(),
            tls_cert_path: None,
            tls_key_path: None,
            enable_http2: default_enable_http2(),
            enable_compression: default_enable_compression(),
            enable_access_log: default_enable_access_log(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
            max_connections: default_max_connections(),
            min_connections: default_min_connections(),
            connection_timeout: default_connection_timeout(),
            idle_timeout: default_idle_timeout(),
            max_lifetime: default_max_lifetime(),
            enable_health_check: default_enable_health_check(),
            enable_ssl: default_enable_ssl(),
            ssl_ca_cert_path: None,
            ssl_client_cert_path: None,
            ssl_client_key_path: None,
            pool_name: default_pool_name(),
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: default_redis_url(),
            pool_size: default_redis_pool_size(),
            default_ttl: default_redis_ttl(),
            connect_timeout: default_redis_connect_timeout(),
            command_timeout: default_redis_command_timeout(),
            enable_tls: default_redis_enable_tls(),
            cluster_mode: default_redis_cluster_mode(),
            sentinel_mode: default_redis_sentinel_mode(),
            sentinel_master_name: None,
            sentinel_nodes: vec![],
            password: None,
            database: default_redis_database(),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: default_jwt_secret(),
            expiration_hours: default_jwt_expiration(),
            refresh_expiration_days: default_refresh_expiration(),
            issuer: default_jwt_issuer(),
            audience: default_jwt_audience(),
            algorithm: default_jwt_algorithm(),
            enable_blacklist: default_enable_jwt_blacklist(),
            blacklist_ttl: default_jwt_blacklist_ttl(),
        }
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            key: default_encryption_key(),
            algorithm: default_encryption_algorithm(),
            iv_length: default_encryption_iv_length(),
            tag_length: default_encryption_tag_length(),
            enable_hardware_acceleration: default_enable_hardware_acceleration(),
            key_rotation_days: default_key_rotation_days(),
        }
    }
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb: default_max_file_size(),
            allowed_formats: default_allowed_formats(),
            max_duration_seconds: default_max_duration(),
            thumbnail_enabled: default_thumbnail_enabled(),
            thumbnail_size: default_thumbnail_size(),
            watermark_enabled: default_watermark_enabled(),
            watermark_path: None,
            watermark_position: default_watermark_position(),
            transcoding_profiles: default_transcoding_profiles(),
            enable_adaptive_bitrate: default_enable_adaptive_bitrate(),
            enable_drm: default_enable_drm(),
            drm_provider: default_drm_provider(),
            enable_content_audit: default_enable_content_audit(),
            audit_provider: default_audit_provider(),
        }
    }
}

impl Default for PaymentConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_payment(),
            default_currency: default_currency(),
            platform_fee_rate: default_platform_fee_rate(),
            min_withdrawal_amount: default_min_withdrawal_amount(),
            max_withdrawal_amount: default_max_withdrawal_amount(),
            withdrawal_processing_hours: default_withdrawal_processing_hours(),
            channels: default_payment_channels(),
            sandbox: default_enable_sandbox(),
            callback_url: default_payment_callback_url(),
            return_url: default_payment_return_url(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_rate_limit(),
            global_limit: default_global_rate_limit(),
            ip_limit: default_ip_rate_limit(),
            user_limit: default_user_rate_limit(),
            upload_limit: default_upload_rate_limit(),
            captcha_limit: default_captcha_rate_limit(),
            window_seconds: default_rate_limit_window(),
            sliding_window: default_enable_sliding_window(),
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_cors(),
            allowed_origins: default_allowed_origins(),
            allowed_methods: default_allowed_methods(),
            allowed_headers: default_allowed_headers(),
            allow_credentials: default_allow_credentials(),
            max_age: default_max_age(),
            expose_headers: default_expose_headers(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            dir: default_log_dir(),
            max_file_size: default_max_log_size(),
            max_files: default_max_log_files(),
            enable_console: default_enable_console(),
            enable_file: default_enable_file(),
            enable_json: default_enable_json(),
            enable_timestamp: default_enable_timestamp(),
            enable_thread_id: default_enable_thread_id(),
            enable_trace_id: default_enable_trace_id(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_telemetry(),
            provider: default_telemetry_provider(),
            endpoint: default_telemetry_endpoint(),
            sampling_rate: default_sampling_rate(),
            enable_metrics: default_enable_metrics(),
            enable_tracing: default_enable_tracing(),
            enable_logs: default_enable_logs(),
            service_name: default_service_name(),
            service_version: default_service_version(),
            deployment_env: default_deployment_env(),
        }
    }
}

impl Default for CloudServiceConfig {
    fn default() -> Self {
        Self {
            default_provider: default_cloud_provider(),
            tencent: TencentCloudConfig::default(),
            aliyun: AliyunCloudConfig::default(),
            aws: AwsCloudConfig::default(),
            huawei: HuaweiCloudConfig::default(),
        }
    }
}

impl Default for TencentCloudConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            secret_id: None,
            secret_key: None,
            region: default_tencent_region(),
            vod: TencentVodConfig::default(),
            cos: TencentCosConfig::default(),
        }
    }
}

impl Default for TencentVodConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            sub_app_id: None,
            storage_region: default_tencent_vod_storage_region(),
            transcode_template: default_tencent_vod_transcode_template(),
            watermark_template_id: None,
            enable_drm: default_enable_drm(),
        }
    }
}

impl Default for TencentCosConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            bucket: None,
            region: default_tencent_cos_region(),
            enable_cdn: default_enable_cdn(),
            cdn_domain: None,
        }
    }
}

impl Default for AliyunCloudConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            access_key_id: None,
            access_key_secret: None,
            region: default_aliyun_region(),
            vod: AliyunVodConfig::default(),
            oss: AliyunOssConfig::default(),
        }
    }
}

impl Default for AliyunVodConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            storage_region: default_aliyun_vod_storage_region(),
            transcode_template_group_id: None,
            watermark_template_id: None,
            enable_drm: default_enable_drm(),
        }
    }
}

impl Default for AliyunOssConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            bucket: None,
            region: default_aliyun_oss_region(),
            enable_cdn: default_enable_cdn(),
            cdn_domain: None,
        }
    }
}

impl Default for AwsCloudConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            access_key_id: None,
            secret_access_key: None,
            region: default_aws_region(),
            s3: AwsS3Config::default(),
        }
    }
}

impl Default for AwsS3Config {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            bucket: None,
            enable_cdn: default_enable_cdn(),
            cloudfront_domain: None,
        }
    }
}

impl Default for HuaweiCloudConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            access_key_id: None,
            secret_access_key: None,
            region: default_huawei_region(),
            obs: HuaweiObsConfig::default(),
        }
    }
}

impl Default for HuaweiObsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            bucket: None,
            region: default_huawei_obs_region(),
            enable_cdn: default_enable_cdn(),
            cdn_domain: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            default_provider: default_storage_provider(),
            local: LocalStorageConfig::default(),
            s3: S3StorageConfig::default(),
            enable_multi_storage: default_enable_multi_storage(),
            strategy: default_storage_strategy(),
        }
    }
}

impl Default for LocalStorageConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            dir: default_local_storage_dir(),
            max_storage_gb: default_local_max_storage(),
            enable_symlink: default_enable_symlink(),
            file_permissions: default_file_permissions(),
        }
    }
}

impl Default for S3StorageConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            endpoint: default_s3_endpoint(),
            region: default_s3_region(),
            bucket: None,
            access_key_id: None,
            secret_access_key: None,
            enable_ssl: default_enable_ssl(),
            path_style: default_enable_path_style(),
        }
    }
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_email(),
            smtp_server: default_smtp_server(),
            smtp_port: default_smtp_port(),
            username: None,
            password: None,
            sender_email: default_sender_email(),
            sender_name: default_sender_name(),
            enable_tls: default_enable_tls(),
            enable_starttls: default_enable_starttls(),
            connect_timeout: default_email_connect_timeout(),
            command_timeout: default_email_command_timeout(),
        }
    }
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_sms(),
            provider: default_sms_provider(),
            access_key_id: None,
            access_key_secret: None,
            sign_name: None,
            template_id: None,
            rate_limit_seconds: default_sms_rate_limit(),
            code_expiry_seconds: default_sms_code_expiry(),
            enable_international: default_enable_international_sms(),
            default_country_code: default_country_code(),
        }
    }
}

impl Default for CdnConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_cdn(),
            provider: default_cdn_provider(),
            domain: None,
            enable_https: default_enable_https(),
            enable_http2: default_enable_http2(),
            cache_policy: default_cdn_cache_policy(),
            cache_ttl: default_cdn_cache_ttl(),
            enable_gzip: default_enable_gzip(),
            enable_brotli: default_enable_brotli(),
            enable_referer: default_enable_referer(),
            allowed_referers: vec![],
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_headers: default_enable_security_headers(),
            enable_csp: default_enable_csp(),
            csp_policy: default_csp_policy(),
            enable_hsts: default_enable_hsts(),
            hsts_max_age: default_hsts_max_age(),
            enable_xss_protection: default_enable_xss_protection(),
            enable_clickjacking_protection: default_enable_clickjacking_protection(),
            enable_mime_sniffing_protection: default_enable_mime_sniffing_protection(),
            enable_referrer_policy: default_enable_referrer_policy(),
            referrer_policy: default_referrer_policy(),
            enable_certificate_pinning: default_enable_certificate_pinning(),
            certificate_pins: vec![],
            enable_request_signing: default_enable_request_signing(),
            signing_key: None,
            signing_algorithm: default_signing_algorithm(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_cache(),
            default_ttl: default_cache_ttl(),
            max_size_mb: default_max_cache_size(),
            cleanup_interval: default_cache_cleanup_interval(),
            strategy: default_cache_strategy(),
            enable_memory: default_enable_memory_cache(),
            enable_redis: default_enable_redis_cache(),
            enable_distributed: default_enable_distributed_cache(),
        }
    }
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_queue(),
            provider: default_queue_provider(),
            redis: RedisQueueConfig::default(),
            rabbitmq: RabbitMqQueueConfig::default(),
            sqs: SqsQueueConfig::default(),
            default_queue: default_queue_name(),
            retries: default_queue_retries(),
            retry_delay: default_queue_retry_delay(),
            max_workers: default_max_workers(),
            worker_idle_timeout: default_worker_idle_timeout(),
        }
    }
}

impl Default for RedisQueueConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            url: default_redis_queue_url(),
            prefix: default_queue_prefix(),
            queue_count: default_queue_count(),
        }
    }
}

impl Default for RabbitMqQueueConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            url: default_rabbitmq_url(),
            exchange: default_exchange_name(),
            exchange_type: default_exchange_type(),
            queue: default_queue_name(),
            routing_key: default_routing_key(),
        }
    }
}

impl Default for SqsQueueConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            queue_url: None,
            region: default_aws_region(),
            access_key_id: None,
            secret_access_key: None,
        }
    }
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            enabled: default_enable_tasks(),
            scheduler: default_task_scheduler(),
            database_cleanup: DatabaseCleanupTaskConfig::default(),
            cache_cleanup: CacheCleanupTaskConfig::default(),
            email_send: EmailSendTaskConfig::default(),
            video_transcode: VideoTranscodeTaskConfig::default(),
            statistics: StatisticsTaskConfig::default(),
            backup: BackupTaskConfig::default(),
        }
    }
}

impl Default for DatabaseCleanupTaskConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval: default_database_cleanup_interval(),
            retention_days: default_retention_days(),
            tables: vec![],
            batch_size: default_batch_size(),
        }
    }
}

impl Default for CacheCleanupTaskConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval: default_cache_cleanup_interval(),
            mode: default_cleanup_mode(),
            ratio: default_cleanup_ratio(),
        }
    }
}

impl Default for EmailSendTaskConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval: default_email_send_interval(),
            batch_size: default_batch_size(),
            retry_count: default_retry_count(),
        }
    }
}

impl Default for VideoTranscodeTaskConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval: default_transcode_interval(),
            max_concurrent: default_max_concurrent_tasks(),
            timeout: default_transcode_timeout(),
            retry_count: default_retry_count(),
        }
    }
}

impl Default for StatisticsTaskConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval: default_statistics_interval(),
            metrics: vec![],
            retention_days: default_retention_days(),
        }
    }
}

impl Default for BackupTaskConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval: default_backup_interval(),
            backup_dir: default_backup_dir(),
            retention_days: default_retention_days(),
            compression: default_compression_algorithm(),
            encrypt: default_encrypt_backup(),
        }
    }
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            enable_registration: default_enable_registration(),
            enable_email_verification: default_enable_email_verification(),
            enable_phone_verification: default_enable_phone_verification(),
            enable_two_factor: default_enable_two_factor(),
            enable_social_login: default_enable_social_login(),
            enable_api_docs: default_enable_api_docs(),
            enable_admin_panel: default_enable_admin_panel(),
            enable_realtime_notifications: default_enable_realtime_notifications(),
            enable_websocket: default_enable_websocket(),
            enable_graphql: default_enable_graphql(),
            enable_search: default_enable_search(),
            enable_recommendations: default_enable_recommendations(),
            enable_analytics: default_enable_analytics(),
            enable_ab_testing: default_enable_ab_testing(),
            enable_experimental: default_enable_experimental_features(),
        }
    }
}

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
    
    
    /// 检查是否启用HTTPS
    pub fn is_https_enabled(&self) -> bool {
        self.server.enable_https && self.server.tls_cert_path.is_some() && self.server.tls_key_path.is_some()
    }
    
    /// 获取TLS配置
    pub fn tls_config(&self) -> Option<(String, String)> {
        if self.is_https_enabled() {
            Some((
                self.server.tls_cert_path.as_ref().unwrap().clone(),
                self.server.tls_key_path.as_ref().unwrap().clone(),
            ))
        } else {
            None
        }
    }
    
    /// 获取环境特定的配置
    pub fn for_environment(env: &str) -> ConfigResult<Self> {
        let mut loader = ConfigLoader::new();
        loader.set_environment(env);
        loader.load()
    }
    
   /// 从环境变量加载配置（自动解密）
    pub fn from_env() -> ConfigResult<Self> {
        let mut loader = ConfigLoader::new();
        let config = loader.load_from_env()?;
        
        // 初始化全局加密器
        crate::encryption::init_global_encryptor()?;
        
        // 解密敏感配置
        let mut decrypted_config = config.clone();
        let encryptor = crate::encryption::get_global_encryptor()?;
        encryptor.decrypt_config(&mut decrypted_config)?;
        
        // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;
        
        Ok(decrypted_config)
    }
    
    /// 从文件加载配置（自动解密）
    pub fn from_file(path: &str) -> ConfigResult<Self> {
        let mut loader = ConfigLoader::new();
        let config = loader.load_from_file(path)?;
        
        // 初始化全局加密器
        crate::encryption::init_global_encryptor()?;
        
        // 解密敏感配置
        let mut decrypted_config = config.clone();
        let encryptor = crate::encryption::get_global_encryptor()?;
        encryptor.decrypt_config(&mut decrypted_config)?;
        
        // 验证解密后的配置
        let validator = crate::validator::ConfigValidator::new();
        validator.validate(&decrypted_config)?;
        
        Ok(decrypted_config)
    }
    
    /// 加密敏感配置
    pub fn encrypt_sensitive_fields(&mut self) -> ConfigResult<()> {
        crate::encryption::init_global_encryptor()?;
        let encryptor = crate::encryption::get_global_encryptor()?;
        encryptor.encrypt_config(self)
    }
    
    /// 解密敏感配置
    pub fn decrypt_sensitive_fields(&mut self) -> ConfigResult<()> {
        crate::encryption::init_global_encryptor()?;
        let encryptor = crate::encryption::get_global_encryptor()?;
        encryptor.decrypt_config(self)
    }
    
    /// 获取解密后的数据库URL
    pub fn get_decrypted_database_url(&self) -> ConfigResult<String> {
        crate::encryption::init_global_encryptor()?;
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
            crate::encryption::init_global_encryptor()?;
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
    
    /// 获取解密后的JWT密钥
    pub fn get_decrypted_jwt_secret(&self) -> ConfigResult<String> {
        crate::encryption::init_global_encryptor()?;
        let encryptor = crate::encryption::get_global_encryptor()?;
        
        if encryptor.is_encrypted_value(&self.jwt.secret) {
            encryptor.decrypt_config_value("jwt.secret", &self.jwt.secret)
        } else {
            Ok(self.jwt.secret.clone())
        }
    }
    
    /// 合并两个配置
    pub fn merge(&mut self, other: Self) {
        // 这里可以实现配置合并逻辑
        // 由于配置结构复杂，这里只实现简单的覆盖逻辑
        *self = other;
    }
    
    /// 获取扩展配置
    pub fn get_extension<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.extensions.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }
    
    /// 设置扩展配置
    pub fn set_extension<T: serde::Serialize>(&mut self, key: &str, value: T) {
        if let Ok(json) = serde_json::to_value(value) {
            self.extensions.insert(key.to_string(), json);
        }
    }
}