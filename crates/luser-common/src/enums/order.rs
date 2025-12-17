

use serde::{Deserialize, Serialize};

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