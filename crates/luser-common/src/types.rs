
use std::{fmt, ops::Deref};

use serde::{Deserialize, Serialize};
use validator::Validate;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::enums::{CloudVendor, Currency, PaymentChannel, PaymentStatus, Role};



/// API响应包装
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Res<T> {
    pub success: bool,
    pub code: u16,
    pub message: String,
    pub data: Option<T>,
    pub timestamp: i64,
}

impl<T> Res<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            code: 200,
            message: "success".to_string(),
            data: Some(data),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
    pub fn ok() -> Self {
        Self {
            success: true,
            code: 200,
            message: "success".to_string(),
            data: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
    pub fn success_with_msg(message: impl Into<String>, data: T) -> Self {
        Self {
            success: true,
            code: 200,
            message: message.into(),
            data: Some(data),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

}

/// 通用ID参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdParam {
    pub id: String,
}

/// 通用批量操作参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchParams {
    pub ids: Vec<String>,
}
/// 安全字符串包装（防止日志泄露敏感信息）
#[derive(Debug, Clone)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Deref for SensitiveString {
    type Target = str;
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for SensitiveString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***SENSITIVE***")
    }
}

/// 文件上传请求
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct FileUploadRequest {
    /// 文件名称
    #[validate(length(min = 1, max = 255))]
    pub filename: String,
    
    /// 文件大小（字节）
    #[validate(range(min = 1, max = 107374182))] // 10GB
    pub file_size: u64,
    
    /// 文件MD5哈希
    #[validate(length(min = 32, max = 32))]
    pub md5_hash: String,
    
    /// 视频时长（秒，可选）
    pub duration: Option<u32>,
    
    /// 视频宽度（可选）
    pub width: Option<u32>,
    
    /// 视频高度（可选）
    pub height: Option<u32>,
}

/// 文件上传响应
#[derive(Debug, Serialize, Deserialize)]
pub struct FileUploadResponse {
    /// 上传URL
    pub upload_url: String,
    
    /// 上传凭证（如果服务商需要）
    pub upload_token: Option<String>,
    
    /// 上传凭证过期时间
    pub expires_at: DateTime<Utc>,
    
    /// 视频ID（服务商返回的）
    pub video_id: String,
    
    /// 上传ID（平台内部的）
    pub upload_id: Uuid,
    
    /// 云服务商
    pub cloud_vendor: CloudVendor,
}

/// 视频播放信息
#[derive(Debug, Serialize, Deserialize)]
pub struct VideoPlayInfo {
    /// 播放URL
    pub play_url: String,
    
    /// 封面URL
    pub cover_url: Option<String>,
    
    /// 播放凭证（如果有DRM保护）
    pub play_token: Option<String>,
    
    /// 播放凭证过期时间
    pub expires_at: DateTime<Utc>,
    
    /// 视频格式列表
    pub formats: Vec<VideoFormat>,
    
    /// 清晰度列表
    pub qualities: Vec<VideoQuality>,
}

/// 视频格式
#[derive(Debug, Serialize, Deserialize)]
pub struct VideoFormat {
    /// 格式名称
    pub name: String,
    
    /// 格式编码
    pub codec: String,
    
    /// 码率（kbps）
    pub bitrate: u32,
    
    /// 播放URL
    pub url: String,
}

/// 视频清晰度
#[derive(Debug, Serialize, Deserialize)]
pub struct VideoQuality {
    /// 清晰度名称（如：360p、720p、1080p）
    pub name: String,
    
    /// 宽度
    pub width: u32,
    
    /// 高度
    pub height: u32,
    
    /// 播放URL
    pub url: String,
}



/// 支付请求
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct PaymentRequest {
    /// 订单ID
    pub order_id: Uuid,
    
    /// 支付金额（单位：分）
    #[validate(range(min = 1, max = 100000000))] // 最大100万元
    pub amount: u64,
    
    /// 货币类型
    pub currency: Currency,
    
    /// 支付渠道
    pub channel: PaymentChannel,
    
    /// 商品描述
    #[validate(length(min = 1, max = 200))]
    pub description: String,
    
    /// 回调URL
    #[validate(url)]
    pub notify_url: String,
    
    /// 返回URL
    #[validate(url)]
    pub return_url: String,
    
    /// 客户端IP
    pub client_ip: String,
}

/// 支付响应
#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentResponse {
    /// 支付URL（用户需要跳转到此URL完成支付）
    pub payment_url: String,
    
    /// 预支付ID（用于查询支付状态）
    pub prepay_id: Option<String>,
    
    /// 平台订单号
    pub out_trade_no: String,
    
    /// 支付二维码URL（可选）
    pub qrcode_url: Option<String>,
    
    /// 支付凭证（用于后续查询）
    pub payment_token: String,
}

/// 支付结果通知
#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentNotification {
    /// 平台订单号
    pub out_trade_no: String,
    
    /// 服务商交易号
    pub transaction_id: String,
    
    /// 支付状态
    pub status: PaymentStatus,
    
    /// 支付金额（单位：分）
    pub amount: u64,
    
    /// 支付完成时间
    pub paid_at: Option<DateTime<Utc>>,
    
    /// 签名
    pub sign: String,
    
    /// 原始通知数据（JSON字符串）
    pub raw_data: String,
}

/// 用户认证令牌
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthToken {
    /// 访问令牌
    pub access_token: String,
    
    /// 令牌类型
    pub token_type: String,
    
    /// 过期时间（秒）
    pub expires_in: i64,
    
    /// 刷新令牌
    pub refresh_token: String,
    
    /// 用户信息
    pub user: UserInfo,
}

/// 用户基本信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserInfo {
    /// 用户ID
    pub id: Uuid,
    
    /// 用户名
    pub username: String,
    
    /// 邮箱
    pub email: String,
    
    /// 显示名称
    pub nick_name: Option<String>,
    
    /// 头像URL
    pub avatar_url: Option<String>,
    
    /// 用户角色
    pub role: Role,
    
    /// 是否为验证创作者
    pub is_verified_creator: bool,
    
    /// 创作者等级
    pub creator_level: i32,
    
    /// 统计信息
    pub stats: UserStats,
}

/// 用户统计信息
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UserStats {
    /// 粉丝数
    pub follower_count: u64,
    
    /// 关注数
    pub following_count: u64,
    
    /// 总收益（分）
    pub total_earnings: u64,
    
    /// 视频数
    pub video_count: u64,
    
    /// 总播放量
    pub total_views: u64,
    
    /// 总点赞数
    pub total_likes: u64,
}

/// 时间范围
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeRange {
    /// 开始时间
    pub start_time: Option<DateTime<Utc>>,
    
    /// 结束时间
    pub end_time: Option<DateTime<Utc>>,
}

impl TimeRange {
    /// 创建时间范围
    pub fn new(start_time: Option<DateTime<Utc>>, end_time: Option<DateTime<Utc>>) -> Self {
        Self { start_time, end_time }
    }
     pub fn today() -> Self {
        let now = Utc::now();
        let start = now.date().and_hms(0, 0, 0);
        let end = now.date().and_hms(23, 59, 59);
        Self {
            start_time: Some(start),
            end_time: Some(end),
        }
    }
    
    pub fn last_7_days() -> Self {
        let end = Utc::now();
        let start = end - Duration::days(7);
        Self {
            start_time: Some(start),
            end_time: Some(end),
        }
    }
    /// 检查时间是否在范围内
    pub fn contains(&self, time: &DateTime<Utc>) -> bool {
        if let Some(start) = &self.start_time {
            if time < start {
                return false;
            }
        }
        
        if let Some(end) = &self.end_time {
            if time > end {
                return false;
            }
        }
        
        true
    }
}

/// 地理位置信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GeoLocation {
    /// 国家
    pub country: Option<String>,
    
    /// 省份
    pub province: Option<String>,
    
    /// 城市
    pub city: Option<String>,
    
    /// 经度
    pub longitude: Option<f64>,
    
    /// 纬度
    pub latitude: Option<f64>,
    
    /// IP地址
    pub ip_address: Option<String>,
}

/// 设备信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    /// 设备类型
    pub device_type: String,
    
    /// 操作系统
    pub os: String,
    
    /// 浏览器
    pub browser: Option<String>,
    
    /// 应用版本
    pub app_version: Option<String>,
    
    /// 设备型号
    pub device_model: Option<String>,
}

