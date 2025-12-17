//! 查询构建器，支持链式调用

use std::collections::HashMap;
use luser_common::{AppError, PaginatedResult};
use sqlx::{FromRow, Pool, Postgres, Row};
use serde_json::Value as JsonValue;

use crate::model::Model;

/// 查询构建器
#[derive(Debug, Clone)]
pub struct QueryBuilder<T: Model> {
    /// 数据库连接池，用于执行最终查询
    pool: Pool<Postgres>,
    
    /// SELECT子句的列列表
    /// 例如："id, name, email" 或 "*"
    select_columns: String,
    
    /// WHERE子句的条件表达式集合
    where_conditions: Vec<String>,
    
    /// WHERE子句的参数值集合
    /// 使用JsonValue包装以支持多种数据类型
    where_params: Vec<JsonValue>,
    
    /// ORDER BY子句
    order_by: Option<String>,
    
    /// LIMIT子句，限制返回记录数
    limit: Option<u64>,
    
    /// OFFSET子句，指定跳过的记录数
    offset: Option<u64>,
    
    /// JOIN子句集合
    /// 例如：["INNER JOIN posts ON users.id = posts.user_id"]
    joins: Vec<String>,
    
    /// GROUP BY子句
    /// 例如："department_id, status"
    group_by: Option<String>,
    
    /// HAVING子句（需与GROUP BY配合使用）
    /// 例如："COUNT(*) > 1"
    having: Option<String>,
    
    /// 类型标记，用于在编译时关联泛型参数T
    /// 使结构体能够保留泛型类型信息而不实际持有该类型的值
    _marker: std::marker::PhantomData<T>,
}

impl<T: Model> QueryBuilder<T> {
    /// 创建新的查询构建器
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self {
            pool,
            select_columns: T::all_fields(),
            where_conditions: Vec::new(),
            where_params: Vec::new(),
            order_by: None,
            limit: None,
            offset: None,
            joins: Vec::new(),
            group_by: None,
            having: None,
            _marker: std::marker::PhantomData,
        }
    }
    
    /// 设置查询字段
    pub fn select(mut self, columns: &str) -> Self {
        self.select_columns = columns.to_string();
        self
    }
    
    /// 添加WHERE条件
    pub fn r#where(mut self, condition: &str) -> Self {
        self.where_conditions.push(condition.to_string());
        self
    }
    
    /// 添加带参数的WHERE条件
    pub fn where_param(mut self, condition: &str, param: JsonValue) -> Self {
        self.where_conditions.push(condition.to_string());
        self.where_params.push(param);
        self
    }
    
    /// 添加多个WHERE条件
    pub fn where_many(mut self, conditions: &[(&str, Option<JsonValue>)]) -> Self {
        for (condition, param) in conditions {
            self.where_conditions.push(condition.to_string());
            if let Some(param) = param {
                self.where_params.push(param.clone());
            }
        }
        self
    }
    
    /// 添加IN条件
    pub fn where_in(mut self, column: &str, values: Vec<JsonValue>) -> Self {
        if !values.is_empty() {
            let placeholders = (1..=values.len())
                .map(|i| format!("${}", self.where_params.len() + i))
                .collect::<Vec<_>>()
                .join(", ");
            
            self.where_conditions.push(format!("{} IN ({})", column, placeholders));
            self.where_params.extend(values);
        }
        self
    }
    
    /// 添加LIKE条件
    pub fn where_like(mut self, column: &str, pattern: &str) -> Self {
        self.where_conditions.push(format!("{} LIKE ${}", column, self.where_params.len() + 1));
        self.where_params.push(JsonValue::String(pattern.to_string()));
        self
    }
    
    /// 添加BETWEEN条件
    pub fn where_between(mut self, column: &str, start: JsonValue, end: JsonValue) -> Self {
        self.where_conditions.push(format!("{} BETWEEN ${} AND ${}", 
            column, 
            self.where_params.len() + 1,
            self.where_params.len() + 2
        ));
        self.where_params.push(start);
        self.where_params.push(end);
        self
    }
    
    /// 添加软删除条件
    pub fn where_not_deleted(mut self) -> Self {
        if T::soft_delete() {
            self.where_conditions.push("deleted_at IS NULL".to_string());
        }
        self
    }
    
    /// 添加排序
    pub fn order_by(mut self, order: &str) -> Self {
        self.order_by = Some(order.to_string());
        self
    }
    
    /// 设置限制
    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
    
    /// 设置偏移量
    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }
    
    /// 设置分页
    pub fn paginate(mut self, page: u64, per_page: u64) -> Self {
        self.limit = Some(per_page);
        self.offset = Some((page - 1) * per_page);
        self
    }
    
    /// 添加JOIN
    pub fn join(mut self, join_clause: &str) -> Self {
        self.joins.push(join_clause.to_string());
        self
    }
    
    /// 设置GROUP BY
    pub fn group_by(mut self, group_by: &str) -> Self {
        self.group_by = Some(group_by.to_string());
        self
    }
    
    /// 设置HAVING条件
    pub fn having(mut self, having: &str) -> Self {
        self.having = Some(having.to_string());
        self
    }
    
    /// 构建SQL语句
    pub fn build_sql(&self) -> String {
        let mut sql = format!("SELECT {} FROM {}", self.select_columns, T::table_name());
        
        // 添加JOIN
        if !self.joins.is_empty() {
            sql.push_str(&format!(" {}", self.joins.join(" ")));
        }
        
        // 添加WHERE条件
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        // 添加GROUP BY
        if let Some(group_by) = &self.group_by {
            sql.push_str(&format!(" GROUP BY {}", group_by));
        }
        
        // 添加HAVING
        if let Some(having) = &self.having {
            sql.push_str(&format!(" HAVING {}", having));
        }
        
        // 添加ORDER BY
        if let Some(order_by) = &self.order_by {
            sql.push_str(&format!(" ORDER BY {}", order_by));
        }
        
        // 添加LIMIT
        if let Some(limit) = self.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }
        
        // 添加OFFSET
        if let Some(offset) = self.offset {
            sql.push_str(&format!(" OFFSET {}", offset));
        }
        
        sql
    }
    
    /// 执行查询并返回结果
    pub async fn fetch_all(self) -> Result<Vec<T>, AppError> 
    where
        T: Send + Unpin + for<'r> FromRow<'r, sqlx::postgres::PgRow>,
        {
        let sql = self.build_sql();
        
        let mut query_builder = sqlx::query_as::<_, T>(&sql);
        
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        query_builder
            .fetch_all(&self.pool)
            .await
            .map_err(AppError::from)
    }
    
    /// 执行查询并返回第一条结果
    pub async fn fetch_one(self) -> Result<Option<T>, AppError> 
    where
        T: Send + Unpin + for<'r> FromRow<'r, sqlx::postgres::PgRow>,
        {
        let sql = self.build_sql();
        
        let mut query_builder = sqlx::query_as::<_, T>(&sql);
        
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        query_builder
            .fetch_optional(&self.pool)
            .await
            .map_err(AppError::from)
    }
    
    /// 执行查询并返回分页结果
    pub async fn fetch_paginated(self, page: u64, per_page: u64) -> Result<PaginatedResult<T>, AppError> 
    where
        T: Send + Unpin + for<'r> FromRow<'r, sqlx::postgres::PgRow>,
        {
        // 先获取总数
        let mut count_sql = format!("SELECT COUNT(*) FROM {}", T::table_name());
        
        if !self.where_conditions.is_empty() {
            count_sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut count_query = sqlx::query_as::<_, (i64,)>(&count_sql);
        
        for param in &self.where_params {
            count_query = count_query.bind(param);
        }
        
        let total: (i64,) = count_query
            .fetch_one(&self.pool)
            .await
           .map_err(AppError::from)?;
        
        // 获取数据
        let mut data_sql = self.build_sql();
        
        // 确保有LIMIT和OFFSET
        if self.limit.is_none() {
            data_sql.push_str(&format!(" LIMIT {}", per_page));
        }
        
        if self.offset.is_none() {
            data_sql.push_str(&format!(" OFFSET {}", (page - 1) * per_page));
        }
        
        let mut data_query = sqlx::query_as::<_, T>(&data_sql);
        
        for param in self.where_params {
            data_query = data_query.bind(param);
        }
        
        let items = data_query
            .fetch_all(&self.pool)
            .await
           .map_err(AppError::from)?;
        
        Ok(PaginatedResult::new(items, total.0 as u64, page, per_page))
    }
    
    /// 执行查询并返回计数
    pub async fn count(self) -> Result<i64, AppError> {
        let mut sql = format!("SELECT COUNT(*) FROM {}", T::table_name());
        
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut query_builder = sqlx::query_as::<_, (i64,)>(&sql);
        
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        let result: (i64,) = query_builder
            .fetch_one(&self.pool)
            .await
          .map_err(AppError::from)?;
        
        Ok(result.0)
    }
    
    /// 执行更新操作
    pub async fn update(self, updates: &HashMap<String, JsonValue>) -> Result<u64, AppError> {
        if updates.is_empty() {
            return Ok(0);
        }
        
        let set_clauses: Vec<String> = updates
            .iter()
            .enumerate()
            .map(|(i, (key, _))| format!("{} = ${}", key, i + 1))
            .collect();
        
        let mut sql = format!("UPDATE {} SET {}", T::table_name(), set_clauses.join(", "));
        
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut query_builder = sqlx::query(&sql);
        
        // 绑定更新参数
        for (_, value) in updates {
            query_builder = query_builder.bind(value);
        }
        
        // 绑定WHERE参数
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        let result = query_builder
            .execute(&self.pool)
            .await
            .map_err(AppError::from)?;
        
        Ok(result.rows_affected())
    }
    
    /// 执行删除操作
    pub async fn delete(self) -> Result<u64, AppError> {
        let mut sql = format!("DELETE FROM {}", T::table_name());
        
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut query_builder = sqlx::query(&sql);
        
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        let result = query_builder
            .execute(&self.pool)
            .await
           .map_err(AppError::from)?;
        
        Ok(result.rows_affected())
    }
    
    /// 执行软删除操作
    pub async fn soft_delete(self) -> Result<u64, AppError> {
        if !T::soft_delete() {
            return Err(AppError::DatabaseError("Model does not support soft delete".to_string()));
        }
        
        let mut sql = format!("UPDATE {} SET deleted_at = $1, updated_at = $2", T::table_name());
        
        if !self.where_conditions.is_empty() {
            sql.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }
        
        let mut query_builder = sqlx::query(&sql);
        
        // 绑定删除时间参数
        query_builder = query_builder.bind(chrono::Utc::now());
        query_builder = query_builder.bind(chrono::Utc::now());
        
        // 绑定WHERE参数
        for param in self.where_params {
            query_builder = query_builder.bind(param);
        }
        
        let result = query_builder
            .execute(&self.pool)
            .await
           .map_err(AppError::from)?;
        
        Ok(result.rows_affected())
    }
}