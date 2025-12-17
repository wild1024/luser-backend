
use serde::{Deserialize, Serialize};

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

