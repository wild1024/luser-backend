//! Model基类，类似ActiveRecord模式

use std::collections::HashMap;
use luser_common::{AppError, PaginatedResult};
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
pub trait Model: Sized + Send + Sync + Unpin + for<'r> FromRow<'r, PgRow> {
    /// 获取表名
    fn table_name() -> &'static str;
    
    /// 获取主键字段名
    fn primary_key() -> &'static str {
        "id"
    }
     /// 创建默认实例
    fn default() -> Self;
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
    
    /// 保存当前实例（新增或更新）
    async fn save(&mut self) -> Result<&Self, AppError>;
    
    /// 更新当前实例
    async fn update(&mut self) -> Result<&Self, AppError>;
    
    /// 删除当前实例
    async fn delete(&self) -> Result<u64, AppError>;
    
    /// 根据ID查找
    async fn find_by_id(id: impl Into<serde_json::Value> + Send) -> Result<Option<Self>, AppError>;
    
    /// 根据条件查找第一个
    async fn find_first(where_clause: Option<&str>, params: Option<&[serde_json::Value]>) -> Result<Option<Self>, AppError>;
    
    /// 根据条件查找所有
    async fn find_all(where_clause: Option<&str>, params: Option<&[serde_json::Value]>) -> Result<Vec<Self>, AppError>;
    
    /// 分页查询
    async fn paginate(page: u64, per_page: u64, filters: Option<HashMap<String, serde_json::Value>>) -> Result<PaginatedResult<Self>, AppError>;
    
    /// 获取关联查询构建器
    fn query() -> QueryBuilder<Self> {
       crate::global::query()
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
        #[derive(Debug, Clone, Serialize, Deserialize,  sqlx::FromRow)]
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
            
            async fn save(&mut self) -> Result<&Self, AppError> {
                // 检查是否为新记录
                let id_value: serde_json::Value = serde_json::to_value(&self.id)
                    .map_err(luser_common::AppError::from)?;
                
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
                        .fetch_one($crate::global::get_db()?)
                        .await
                        .map_err(luser_common::AppError::from)?;;
                    
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
                        .fetch_one($crate::global::get_db()?)
                        .await
                       .map_err(luser_common::AppError::from)?;
                    
                    *self = result;
                }
                
                Ok(self)
            }
            
            async fn update(&mut self) -> Result<&Self, AppError> {
                self.save().await
            }
            
            async fn delete(&self) -> Result<u64, AppError> {
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
                        .execute($crate::global::get_db()?)
                        .await
                       .map_err(luser_common::AppError::from)?;
                    
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
                        .execute($crate::global::get_db()?)
                        .await
                        .map_err(luser_common::AppError::from)?;
                    
                    Ok(result.rows_affected())
                }
            }
            
            async fn find_by_id(id: impl Into<serde_json::Value> + Send) -> Result<Option<Self>, AppError> {
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
                    .fetch_optional($crate::global::get_db()?)
                    .await
                   .map_err(luser_common::AppError::from)
            }
            
            async fn find_first(where_clause: Option<&str>, params: Option<&[serde_json::Value]>) -> Result<Option<Self>, AppError> {
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
                    .fetch_optional($crate::global::get_db()?)
                    .await
                    .map_err(luser_common::AppError::from)
            }
            
            async fn find_all(where_clause: Option<&str>, params: Option<&[serde_json::Value]>) -> Result<Vec<Self>, AppError> {
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
                    .fetch_all($crate::global::get_db()?)
                    .await
                   .map_err(luser_common::AppError::from)
            }
            
            async fn paginate(page: u64, per_page: u64, filters: Option<HashMap<String, serde_json::Value>>) -> Result<PaginatedResult<Self>, AppError> {
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
                        .fetch_one($crate::global::get_db()?)
                        .await
                } else {
                    let mut query_builder = sqlx::query_as(&count_query);
                    for param in &params {
                        query_builder = query_builder.bind(param);
                    }
                    query_builder.fetch_one($crate::global::get_db()?).await
                }
                .map_err(luser_common::AppError::from)?;
                
                // 获取数据
                let items = if params.is_empty() {
                    sqlx::query_as::<_, Self>(&query)
                        .fetch_all($crate::global::get_db()?)
                        .await
                } else {
                    let mut query_builder = sqlx::query_as::<_, Self>(&query);
                    for param in &params {
                        query_builder = query_builder.bind(param);
                    }
                    query_builder.fetch_all($crate::global::get_db()?).await
                }
               .map_err(luser_common::AppError::from)?;
                
                Ok(PaginatedResult::new(items, total.0 as u64, page, per_page))
            }
        }
    };
}