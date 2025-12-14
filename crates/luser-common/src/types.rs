use std::fmt;
use serde::{Deserialize, Serialize};
use validator::Validate;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::validation::*;

/// API响应封装
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// 是否成功
    pub success: bool,
    /// 返回数据
    pub data: Option<T>,
    /// 错误信息
    pub error: Option<ApiError>,
    /// 请求ID
    pub request_id: String,
    /// 时间戳
    pub timestamp: DateTime<Utc>,
}

impl<T> ApiResponse<T> {
    /// 创建成功响应
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            request_id: generate_request_id(),
            timestamp: Utc::now(),
        }
    }
    
    /// 创建错误响应
    pub fn error(error: ApiError) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            request_id: generate_request_id(),
            timestamp: Utc::now(),
        }
    }
    
    /// 创建空成功响应
    pub fn empty() -> Self {
        Self {
            success: true,
            data: None,
            error: None,
            request_id: generate_request_id(),
            timestamp: Utc::now(),
        }
    }
}

/// API错误信息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiError {
    /// 错误代码
    pub code: String,
    /// 错误消息
    pub message: String,
    /// 错误详情
    pub details: Option<serde_json::Value>,
    /// HTTP状态码
    pub status_code: u16,
}

impl ApiError {
    /// 创建新的API错误
    pub fn new(code: &str, message: &str, status_code: u16) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            details: None,
            status_code,
        }
    }
    
    /// 添加错误详情
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

/// 分页请求参数
#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct Pagination {
    /// 页码（从1开始）
    #[validate(range(min = 1))]
    pub page: u32,
    
    /// 每页大小
    #[validate(range(min = 1, max = 100))]
    pub page_size: u32,
    
    /// 排序字段
    pub sort_by: Option<String>,
    
    /// 排序方向：asc/desc
    pub sort_order: Option<String>,
    
    /// 搜索关键词
    pub keyword: Option<String>,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
            sort_by: None,
            sort_order: None,
            keyword: None,
        }
    }
}

/// 分页响应
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// 数据列表
    pub items: Vec<T>,
    
    /// 总记录数
    pub total: u64,
    
    /// 总页数
    pub total_pages: u32,
    
    /// 当前页码
    pub current_page: u32,
    
    /// 每页大小
    pub page_size: u32,
    
    /// 是否有下一页
    pub has_next: bool,
    
    /// 是否有上一页
    pub has_prev: bool,
}

impl<T> PaginatedResponse<T> {
    /// 创建分页响应
    pub fn new(items: Vec<T>, total: u64, pagination: Pagination) -> Self {
        let total_pages = ((total as f64) / (pagination.page_size as f64)).ceil() as u32;
        let has_next = pagination.page < total_pages;
        let has_prev = pagination.page > 1;
        
        Self {
            items,
            total,
            total_pages,
            current_page: pagination.page,
            page_size: pagination.page_size,
            has_next,
            has_prev,
        }
    }
    
    /// 创建空分页响应
    pub fn empty(pagination: Pagination) -> Self {
        Self {
            items: Vec::new(),
            total: 0,
            total_pages: 0,
            current_page: pagination.page,
            page_size: pagination.page_size,
            has_next: false,
            has_prev: false,
        }
    }
}

/// 用户角色
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
pub enum Role {
    /// 普通用户
    User,
    /// 内容创作者
    Creator,
    /// 管理员
    Admin,
    /// 超级管理员
    SuperAdmin,
}

impl Role {
    /// 获取所有角色
    pub fn all() -> Vec<Self> {
        vec![Self::User, Self::Creator, Self::Admin, Self::SuperAdmin]
    }
    
    /// 检查是否有权限
    pub fn has_permission(&self, required_role: Role) -> bool {
        match (self, required_role) {
            (Self::SuperAdmin, _) => true,
            (Self::Admin, Role::Admin | Role::Creator | Role::User) => true,
            (Self::Creator, Role::Creator | Role::User) => true,
            (Self::User, Role::User) => true,
            _ => false,
        }
    }
    
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Creator => "creator",
            Self::Admin => "admin",
            Self::SuperAdmin => "super_admin",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(Self::User),
            "creator" => Ok(Self::Creator),
            "admin" => Ok(Self::Admin),
            "super_admin" => Ok(Self::SuperAdmin),
            _ => Err(format!("无效的角色: {}", s)),
        }
    }
}

/// 用户状态
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
pub enum UserStatus {
    /// 活跃
    Active,
    /// 停用
    Suspended,
    /// 封禁
    Banned,
    /// 已删除
    Deleted,
}

impl UserStatus {
    /// 检查用户是否可用
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
    
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Banned => "banned",
            Self::Deleted => "deleted",
        }
    }
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 支付状态
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
pub enum PaymentStatus {
    /// 待支付
    Pending,
    /// 处理中
    Processing,
    /// 支付成功
    Success,
    /// 支付失败
    Failed,
    /// 已退款
    Refunded,
    /// 已取消
    Cancelled,
}

impl PaymentStatus {
    /// 检查是否完成支付
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Success | Self::Refunded | Self::Cancelled)
    }
    
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Refunded => "refunded",
            Self::Cancelled => "cancelled",
        }
    }
}

/// 视频状态
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
pub enum VideoStatus {
    /// 待上传
    Pending,
    /// 上传中
    Uploading,
    /// 转码中
    Transcoding,
    /// 审核中
    Reviewing,
    /// 已发布
    Published,
    /// 未通过审核
    Rejected,
    /// 已下架
    Offline,
    /// 已删除
    Deleted,
}

impl VideoStatus {
    /// 检查是否可播放
    pub fn is_playable(&self) -> bool {
        matches!(self, Self::Published)
    }
    
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Uploading => "uploading",
            Self::Transcoding => "transcoding",
            Self::Reviewing => "reviewing",
            Self::Published => "published",
            Self::Rejected => "rejected",
            Self::Offline => "offline",
            Self::Deleted => "deleted",
        }
    }
}

/// 云服务商类型
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
pub enum CloudVendor {
    /// 腾讯云点播
    TencentVod,
    /// 阿里云点播
    AliyunVod,
}

impl CloudVendor {
    /// 获取所有云服务商
    pub fn all() -> Vec<Self> {
        vec![Self::TencentVod, Self::AliyunVod]
    }
    
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TencentVod => "tencent_vod",
            Self::AliyunVod => "aliyun_vod",
        }
    }
}

impl std::fmt::Display for CloudVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 支付渠道
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
pub enum PaymentChannel {
    /// 支付宝
    Alipay,
    /// 微信支付
    Wechatpay,
}

impl PaymentChannel {
    /// 获取所有支付渠道
    pub fn all() -> Vec<Self> {
        vec![Self::Alipay, Self::Wechatpay]
    }
    
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alipay => "alipay",
            Self::Wechatpay => "wechatpay",
        }
    }
}

/// 订阅计划类型
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
pub enum SubscriptionPlan {
    /// 免费
    Free,
    /// 月度订阅
    Monthly,
    /// 季度订阅
    Quarterly,
    /// 年度订阅
    Yearly,
    /// 终身订阅
    Lifetime,
}

impl SubscriptionPlan {
    /// 获取所有订阅计划
    pub fn all() -> Vec<Self> {
        vec![
            Self::Free,
            Self::Monthly,
            Self::Quarterly,
            Self::Yearly,
            Self::Lifetime,
        ]
    }
    
    /// 获取订阅时长（天）
    pub fn duration_days(&self) -> Option<u32> {
        match self {
            Self::Free => None,
            Self::Monthly => Some(30),
            Self::Quarterly => Some(90),
            Self::Yearly => Some(365),
            Self::Lifetime => None,
        }
    }
    
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Monthly => "monthly",
            Self::Quarterly => "quarterly",
            Self::Yearly => "yearly",
            Self::Lifetime => "lifetime",
        }
    }
}

/// 货币类型
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "varchar")]
pub enum Currency {
    /// 人民币
    CNY,
    /// 美元
    USD,
    /// 欧元
    EUR,
}

impl Currency {
    /// 获取所有货币
    pub fn all() -> Vec<Self> {
        vec![Self::CNY, Self::USD, Self::EUR]
    }
    
    /// 转换为ISO 4217代码
    pub fn iso_code(&self) -> &'static str {
        match self {
            Self::CNY => "CNY",
            Self::USD => "USD",
            Self::EUR => "EUR",
        }
    }
    
    /// 获取货币符号
    pub fn symbol(&self) -> &'static str {
        match self {
            Self::CNY => "¥",
            Self::USD => "$",
            Self::EUR => "€",
        }
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

/// 生成请求ID
fn generate_request_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let random_number: u32 = rng.random();
    format!("{}-{}", chrono::Utc::now().timestamp_millis(), random_number)
}