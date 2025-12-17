
use serde::{Deserialize, Serialize};

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