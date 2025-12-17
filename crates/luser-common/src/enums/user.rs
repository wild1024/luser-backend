
use serde::{Deserialize, Serialize};

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