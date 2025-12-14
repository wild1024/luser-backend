//! 常量定义

/// 应用常量
pub const APP_NAME: &str = "luser-platform";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_DESCRIPTION: &str = "付费订阅视频平台";

/// 数据库常量
pub const DEFAULT_PAGE_SIZE: u32 = 20;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const DEFAULT_PAGE: u32 = 1;

/// 时间常量（秒）
pub const ONE_MINUTE: u64 = 60;
pub const ONE_HOUR: u64 = 60 * 60;
pub const ONE_DAY: u64 = 24 * 60 * 60;
pub const ONE_WEEK: u64 = 7 * 24 * 60 * 60;
pub const ONE_MONTH: u64 = 30 * 24 * 60 * 60;
pub const ONE_YEAR: u64 = 365 * 24 * 60 * 60;

/// JWT常量
pub const JWT_ACCESS_TOKEN_EXPIRE: i64 = 24 * 60 * 60; // 24小时
pub const JWT_REFRESH_TOKEN_EXPIRE: i64 = 30 * 24 * 60 * 60; // 30天

/// 缓存常量
pub const CACHE_TTL_SHORT: u64 = 5 * 60; // 5分钟
pub const CACHE_TTL_MEDIUM: u64 = 30 * 60; // 30分钟
pub const CACHE_TTL_LONG: u64 = 24 * 60 * 60; // 24小时

/// 验证码常量
pub const CAPTCHA_EXPIRE_SECONDS: u64 = 5 * 60; // 5分钟
pub const CAPTCHA_LENGTH: usize = 6;
pub const SMS_CODE_EXPIRE_SECONDS: u64 = 10 * 60; // 10分钟

/// 文件上传常量
pub const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024 * 1024; // 10GB
pub const MAX_IMAGE_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10MB
pub const MAX_VIDEO_DURATION_SECONDS: u32 = 24 * 60 * 60; // 24小时

/// 允许的文件扩展名
pub const ALLOWED_IMAGE_EXTENSIONS: [&str; 5] = ["jpg", "jpeg", "png", "gif", "webp"];
pub const ALLOWED_VIDEO_EXTENSIONS: [&str; 6] = ["mp4", "mov", "avi", "mkv", "flv", "webm"];
pub const ALLOWED_DOCUMENT_EXTENSIONS: [&str; 5] = ["pdf", "doc", "docx", "txt", "md"];

/// 视频转码配置
pub const VIDEO_TRANSCODE_PROFILES: [(&str, u32, u32, u32); 4] = [
    ("360p", 640, 360, 800),
    ("480p", 854, 480, 1200),
    ("720p", 1280, 720, 2500),
    ("1080p", 1920, 1080, 5000),
];

/// 支付常量
pub const PAYMENT_TIMEOUT_SECONDS: u64 = 15 * 60; // 15分钟
pub const REFUND_TIMEOUT_DAYS: u32 = 7; // 7天
pub const WITHDRAWAL_MIN_AMOUNT: i64 = 10000; // 100元（分）
pub const WITHDRAWAL_MAX_AMOUNT: i64 = 5000000; // 50000元（分）

/// 创作者等级配置
pub const CREATOR_LEVELS: [(i32, f64, u64); 5] = [
    (1, 0.5, 0),    // 等级1，50%分成，0粉丝要求
    (2, 0.6, 1000), // 等级2，60%分成，1000粉丝
    (3, 0.7, 10000), // 等级3，70%分成，10000粉丝
    (4, 0.8, 50000), // 等级4，80%分成，50000粉丝
    (5, 0.9, 100000), // 等级5，90%分成，100000粉丝
];

/// 订阅价格（分）
pub const SUBSCRIPTION_PRICES: [(crate::SubscriptionPlan, i64); 5] = [
    (crate::SubscriptionPlan::Free, 0),
    (crate::SubscriptionPlan::Monthly, 2990),   // 29.9元
    (crate::SubscriptionPlan::Quarterly, 7990), // 79.9元
    (crate::SubscriptionPlan::Yearly, 29990),   // 299.9元
    (crate::SubscriptionPlan::Lifetime, 99990), // 999.9元
];

/// 费率配置（百分比）
pub const PLATFORM_FEE_RATE: f64 = 0.2; // 平台手续费20%
pub const PAYMENT_CHANNEL_FEE_RATE: f64 = 0.006; // 支付渠道手续费0.6%

/// 安全常量
pub const PASSWORD_MIN_LENGTH: usize = 8;
pub const PASSWORD_MAX_LENGTH: usize = 100;
pub const USERNAME_MIN_LENGTH: usize = 3;
pub const USERNAME_MAX_LENGTH: usize = 50;

/// 请求频率限制
pub const RATE_LIMIT_WINDOW_SECONDS: u64 = 60;
pub const RATE_LIMIT_MAX_REQUESTS: u32 = 100;
pub const RATE_LIMIT_UPLOAD_MAX_REQUESTS: u32 = 10;
pub const RATE_LIMIT_PAYMENT_MAX_REQUESTS: u32 = 30;

/// 错误代码
pub mod error_codes {
    // 通用错误
    pub const SUCCESS: &str = "SUCCESS";
    pub const UNKNOWN_ERROR: &str = "UNKNOWN_ERROR";
    pub const VALIDATION_ERROR: &str = "VALIDATION_ERROR";
    pub const DATABASE_ERROR: &str = "DATABASE_ERROR";
    pub const NETWORK_ERROR: &str = "NETWORK_ERROR";
    
    // 认证授权错误
    pub const AUTHENTICATION_FAILED: &str = "AUTHENTICATION_FAILED";
    pub const INVALID_TOKEN: &str = "INVALID_TOKEN";
    pub const TOKEN_EXPIRED: &str = "TOKEN_EXPIRED";
    pub const PERMISSION_DENIED: &str = "PERMISSION_DENIED";
    pub const INVALID_CREDENTIALS: &str = "INVALID_CREDENTIALS";
    
    // 用户相关错误
    pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
    pub const USER_ALREADY_EXISTS: &str = "USER_ALREADY_EXISTS";
    pub const USER_DISABLED: &str = "USER_DISABLED";
    pub const INSUFFICIENT_BALANCE: &str = "INSUFFICIENT_BALANCE";
    
    // 视频相关错误
    pub const VIDEO_NOT_FOUND: &str = "VIDEO_NOT_FOUND";
    pub const VIDEO_UPLOAD_FAILED: &str = "VIDEO_UPLOAD_FAILED";
    pub const VIDEO_TRANSCODE_FAILED: &str = "VIDEO_TRANSCODE_FAILED";
    pub const VIDEO_REVIEW_FAILED: &str = "VIDEO_REVIEW_FAILED";
    pub const VIDEO_ACCESS_DENIED: &str = "VIDEO_ACCESS_DENIED";
    
    // 支付相关错误
    pub const PAYMENT_FAILED: &str = "PAYMENT_FAILED";
    pub const PAYMENT_TIMEOUT: &str = "PAYMENT_TIMEOUT";
    pub const REFUND_FAILED: &str = "REFUND_FAILED";
    pub const INVALID_PAYMENT_SIGNATURE: &str = "INVALID_PAYMENT_SIGNATURE";
    
    // 云服务错误
    pub const CLOUD_SERVICE_ERROR: &str = "CLOUD_SERVICE_ERROR";
    pub const CLOUD_CONFIG_NOT_FOUND: &str = "CLOUD_CONFIG_NOT_FOUND";
    pub const CLOUD_UPLOAD_FAILED: &str = "CLOUD_UPLOAD_FAILED";
    
    // 业务错误
    pub const INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
    pub const ORDER_NOT_FOUND: &str = "ORDER_NOT_FOUND";
    pub const SUBSCRIPTION_EXPIRED: &str = "SUBSCRIPTION_EXPIRED";
    pub const RATE_LIMIT_EXCEEDED: &str = "RATE_LIMIT_EXCEEDED";
    pub const SERVICE_UNAVAILABLE: &str = "SERVICE_UNAVAILABLE";
}

/// 环境变量名称
pub mod env_vars {
    pub const DATABASE_URL: &str = "DATABASE_URL";
    pub const REDIS_URL: &str = "REDIS_URL";
    pub const JWT_SECRET: &str = "JWT_SECRET";
    pub const ENCRYPTION_KEY: &str = "ENCRYPTION_KEY";
    pub const RUN_MODE: &str = "RUN_MODE";
    pub const LOG_LEVEL: &str = "LOG_LEVEL";
    pub const API_HOST: &str = "API_HOST";
    pub const API_PORT: &str = "API_PORT";
    pub const CDN_DOMAIN: &str = "CDN_DOMAIN";
}

/// 运行模式
pub mod run_modes {
    pub const DEVELOPMENT: &str = "development";
    pub const TESTING: &str = "testing";
    pub const STAGING: &str = "staging";
    pub const PRODUCTION: &str = "production";
}

/// HTTP头部常量
pub mod headers {
    pub const AUTHORIZATION: &str = "Authorization";
    pub const X_API_KEY: &str = "X-API-Key";
    pub const X_REQUEST_ID: &str = "X-Request-ID";
    pub const X_TRACE_ID: &str = "X-Trace-ID";
    pub const X_USER_ID: &str = "X-User-ID";
    pub const X_CLIENT_VERSION: &str = "X-Client-Version";
    pub const X_DEVICE_ID: &str = "X-Device-ID";
}

/// 内容类型
pub mod content_types {
    pub const JSON: &str = "application/json";
    pub const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
    pub const MULTIPART_FORM_DATA: &str = "multipart/form-data";
    pub const OCTET_STREAM: &str = "application/octet-stream";
}

/// 路由前缀
pub mod route_prefixes {
    pub const API_V1: &str = "/api/v1";
    pub const ADMIN_API_V1: &str = "/admin/api/v1";
    pub const AUTH: &str = "/auth";
    pub const UPLOAD: &str = "/upload";
    pub const PAYMENT: &str = "/payment";
    pub const VIDEO: &str = "/video";
    pub const USER: &str = "/user";
    pub const CREATOR: &str = "/creator";
    pub const SUBSCRIPTION: &str = "/subscription";
}

/// 腾讯云VOD常量
pub mod tencent_vod {
    pub const DEFAULT_REGION: &str = "ap-guangzhou";
    pub const UPLOAD_TOKEN_EXPIRE_HOURS: u32 = 24;
    pub const PLAY_TOKEN_EXPIRE_SECONDS: u32 = 3600;
    pub const TRANSCODE_TEMPLATE: &str = "LongVideoPreset";
}

/// 阿里云VOD常量
pub mod aliyun_vod {
    pub const DEFAULT_REGION: &str = "cn-shanghai";
    pub const UPLOAD_TOKEN_EXPIRE_HOURS: u32 = 24;
    pub const PLAY_TOKEN_EXPIRE_SECONDS: u32 = 3600;
}

/// 支付宝常量
pub mod alipay {
    pub const API_VERSION: &str = "1.0";
    pub const SIGN_TYPE_RSA2: &str = "RSA2";
    pub const CHARSET_UTF8: &str = "UTF-8";
    pub const FORMAT_JSON: &str = "json";
}

/// 微信支付常量
pub mod wechatpay {
    pub const API_VERSION: &str = "v3";
    pub const SIGN_TYPE_RSA: &str = "RSA";
    pub const SIGN_TYPE_HMAC_SHA256: &str = "HMAC-SHA256";
}