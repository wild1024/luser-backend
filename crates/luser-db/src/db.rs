//! Db类，提供类似JFinal的链式调用API

use chrono::{DateTime, Utc};
use luser_common::{AppError, PaginatedResult};
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres, postgres::PgRow};
use std::collections::HashMap;

use crate::{global::get_db, model::Model, query::QueryBuilder};

/// Db类，提供链式调用API
#[derive(Debug, Clone)]
pub struct Db<T: Model> {
    model: T,
    pool: Pool<Postgres>,
}

impl<T: Model> Db<T> {
    /// 创建新的Db实例
    pub fn new(model: T) -> Self {
        let pool = get_db().expect("数据库未初始化，请先调用 init()");

        Self { model, pool }
    }
    /// 获取底层模型
    pub fn model(&self) -> &T {
        &self.model
    }

    /// 设置查询字段
    pub fn select(self, columns: &str) -> QueryBuilder<T> {
        let mut builder = QueryBuilder::new(self.pool);
        builder.select(columns)
    }

    /// 设置WHERE条件
    pub fn r#where(self, condition: &str) -> QueryBuilder<T> {
        let mut builder = QueryBuilder::new(self.pool);
        builder.r#where(condition)
    }

    /// 设置WHERE条件（使用参数）
    pub fn where_param(self, condition: &str, param: JsonValue) -> QueryBuilder<T> {
        let mut builder = QueryBuilder::new(self.pool);
        builder.where_param(condition, param)
    }

    /// 设置排序
    pub fn order_by(self, order: &str) -> QueryBuilder<T> {
        let mut builder = QueryBuilder::new(self.pool);
        builder.order_by(order)
    }

    /// 设置分页
    pub fn paginate(self, page: u64, per_page: u64) -> QueryBuilder<T> {
        let mut builder = QueryBuilder::new(self.pool);
        builder.paginate(page, per_page)
    }

    /// 查找所有记录
    pub async fn find_all(&self) -> Result<Vec<T>, AppError> {
        T::find_all(None, None).await
    }

    /// 根据ID查找
    pub async fn find_by_id(&self, id: impl Into<JsonValue> + Send) -> Result<Option<T>, AppError> {
        T::find_by_id(id).await
    }

    /// 查找第一条记录
    pub async fn find_first(&self) -> Result<Option<T>, AppError> {
        T::find_first(None, None).await
    }

    /// 根据条件查找第一条记录
    pub async fn find_first_where(
        &self,
        condition: &str,
        params: Option<&[JsonValue]>,
    ) -> Result<Option<T>, AppError> {
        T::find_first(Some(condition), params).await
    }

    /// 根据条件查找所有记录
    pub async fn find_all_where(
        &self,
        condition: &str,
        params: Option<&[JsonValue]>,
    ) -> Result<Vec<T>, AppError> {
        T::find_all(Some(condition), params).await
    }

    /// 分页查询
    pub async fn paginate_where(
        &self,
        page: u64,
        per_page: u64,
        condition: Option<&str>,
        params: Option<&[JsonValue]>,
    ) -> Result<PaginatedResult<T>, AppError> {
        // 构建查询
        let mut query = format!("SELECT {} FROM {}", T::all_fields(), T::table_name());
        let mut count_query = format!("SELECT COUNT(*) FROM {}", T::table_name());

        let mut where_clauses = Vec::new();
        let mut query_params = Vec::new();

        // 添加软删除条件
        if T::soft_delete() {
            where_clauses.push("deleted_at IS NULL".to_string());
        }

        // 添加自定义条件
        if let Some(condition) = condition {
            where_clauses.push(condition.to_string());
        }

        // 添加参数
        if let Some(params) = params {
            for param in params {
                query_params.push(param.clone());
            }
        }

        // 构建WHERE子句
        if !where_clauses.is_empty() {
            let where_clause = where_clauses.join(" AND ");
            query.push_str(&format!(" WHERE {}", where_clause));
            count_query.push_str(&format!(" WHERE {}", where_clause));
        }

        // 添加分页
        let offset = (page - 1) * per_page;
        query.push_str(&format!(" LIMIT {} OFFSET {}", per_page, offset));

        // 获取总数
        let total: (i64,) = if query_params.is_empty() {
            sqlx::query_as(&count_query).fetch_one(&self.pool).await
        } else {
            let mut query_builder = sqlx::query_as(&count_query);
            for param in &query_params {
                query_builder = query_builder.bind(param);
            }
            query_builder.fetch_one(&self.pool).await
        }
        .map_err(AppError::from)?;

        // 获取数据
        let items = if query_params.is_empty() {
            sqlx::query_as::<_, T>(&query).fetch_all(&self.pool).await
        } else {
            let mut query_builder = sqlx::query_as::<_, T>(&query);
            for param in &query_params {
                query_builder = query_builder.bind(param);
            }
            query_builder.fetch_all(&self.pool).await
        }
        .map_err(AppError::from)?;

        Ok(PaginatedResult::new(items, total.0 as u64, page, per_page))
    }

    /// 统计记录数
    pub async fn count(&self) -> Result<i64, AppError> {
        let query = if T::soft_delete() {
            format!(
                "SELECT COUNT(*) FROM {} WHERE deleted_at IS NULL",
                T::table_name()
            )
        } else {
            format!("SELECT COUNT(*) FROM {}", T::table_name())
        };

        let result: (i64,) = sqlx::query_as(&query)
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::from)?;

        Ok(result.0)
    }

    /// 根据条件统计记录数
    pub async fn count_where(
        &self,
        condition: &str,
        params: Option<&[JsonValue]>,
    ) -> Result<i64, AppError> {
        let mut query = format!("SELECT COUNT(*) FROM {}", T::table_name());

        let mut where_clauses = Vec::new();
        if T::soft_delete() {
            where_clauses.push("deleted_at IS NULL".to_string());
        }

        if !condition.is_empty() {
            where_clauses.push(condition.to_string());
        }

        if !where_clauses.is_empty() {
            query.push_str(&format!(" WHERE {}", where_clauses.join(" AND ")));
        }

        let mut query_builder = sqlx::query_as(&query);

        if let Some(params) = params {
            for param in params {
                query_builder = query_builder.bind(param);
            }
        }

        let result: (i64,) = query_builder
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::from)?;

        Ok(result.0)
    }

    /// 检查记录是否存在
    pub async fn exists(&self, id: impl Into<JsonValue> + Send) -> Result<bool, AppError> {
        let id_value = id.into();
        let query = if T::soft_delete() {
            format!(
                "SELECT 1 FROM {} WHERE {} = $1 AND deleted_at IS NULL",
                T::table_name(),
                T::primary_key()
            )
        } else {
            format!(
                "SELECT 1 FROM {} WHERE {} = $1",
                T::table_name(),
                T::primary_key()
            )
        };

        let result: Option<(i32,)> = sqlx::query_as(&query)
            .bind(id_value)
            .fetch_optional(&self.pool)
            .await
            .map_err(AppError::from)?;

        Ok(result.is_some())
    }

    /// 删除记录
    pub async fn delete_by_id(&self, id: impl Into<JsonValue> + Send) -> Result<u64, AppError> {
        let id_value = id.into();

        if T::soft_delete() {
            // 软删除
            let query = format!(
                "UPDATE {} SET deleted_at = $1, updated_at = $2 WHERE {} = $3 AND deleted_at IS NULL",
                T::table_name(),
                T::primary_key()
            );

            let result = sqlx::query(&query)
                .bind(Utc::now())
                .bind(Utc::now())
                .bind(id_value)
                .execute(&self.pool)
                .await
                .map_err(AppError::from)?;

            Ok(result.rows_affected())
        } else {
            // 硬删除
            let query = format!(
                "DELETE FROM {} WHERE {} = $1",
                T::table_name(),
                T::primary_key()
            );

            let result = sqlx::query(&query)
                .bind(id_value)
                .execute(&self.pool)
                .await
                .map_err(AppError::from)?;

            Ok(result.rows_affected())
        }
    }

    /// 批量删除
    pub async fn delete_by_ids(
        &self,
        ids: &[impl Into<JsonValue> + Clone + Send],
    ) -> Result<u64, AppError> {
        let id_values: Vec<JsonValue> = ids.iter().map(|id| id.clone().into()).collect();

        if T::soft_delete() {
            // 软删除
            let query = format!(
                "UPDATE {} SET deleted_at = $1, updated_at = $2 WHERE {} = ANY($3) AND deleted_at IS NULL",
                T::table_name(),
                T::primary_key()
            );

            let result = sqlx::query(&query)
                .bind(Utc::now())
                .bind(Utc::now())
                .bind(id_values)
                .execute(&self.pool)
                .await
                .map_err(AppError::from)?;

            Ok(result.rows_affected())
        } else {
            // 硬删除
            let query = format!(
                "DELETE FROM {} WHERE {} = ANY($1)",
                T::table_name(),
                T::primary_key()
            );

            let result = sqlx::query(&query)
                .bind(id_values)
                .execute(&self.pool)
                .await
                .map_err(AppError::from)?;

            Ok(result.rows_affected())
        }
    }

    /// 执行原始SQL查询
    pub async fn execute_sql(
        &self,
        sql: &str,
        params: Option<&[JsonValue]>,
    ) -> Result<u64, AppError> {
        let mut query_builder = sqlx::query(sql);

        if let Some(params) = params {
            for param in params {
                query_builder = query_builder.bind(param);
            }
        }

        let result = query_builder
            .execute(&self.pool)
            .await
            .map_err(AppError::from)?;

        Ok(result.rows_affected())
    }

    /// 执行原始SQL查询并返回结果
    pub async fn query_sql<R>(
        &self,
        sql: &str,
        params: Option<&[JsonValue]>,
    ) -> Result<Vec<R>, AppError>
    where
        R: Send + Unpin,
        for<'r> R: sqlx::FromRow<'r, sqlx::postgres::PgRow> + DeserializeOwned,
    {
        let mut query_builder = sqlx::query_as::<_, R>(sql);

        if let Some(params) = params {
            for param in params {
                query_builder = query_builder.bind(param);
            }
        }

        let result = query_builder
            .fetch_all(&self.pool)
            .await
            .map_err(AppError::from)?;

        Ok(result)
    }
}

/// 便捷函数：创建Db实例
pub fn use_model<T: Model>() -> Db<T> {
    Db::new(T::default())
}
