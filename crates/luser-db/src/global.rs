//! 全局数据库管理模块


use std::sync::Arc;
use luser_config::get_config;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use luser_common::AppError;

use crate::{db, pool::create_pool};

// 全局数据库实例
static GLOBAL_DB: OnceCell<Arc<RwLock<Option<Pool<Postgres>>>>> = OnceCell::new();

/// 初始化全局数据库连接池
pub async fn init_db() -> Result<(), AppError> {
    let config = get_config()?;
    let pool = create_pool(&config.database).await?;
    
    GLOBAL_DB
        .set(Arc::new(RwLock::new(Some(pool))))
        .map_err(|_| AppError::DatabaseError("全局数据库已初始化".to_string()))?;
    
    tracing::info!("全局数据库连接池初始化完成");
    Ok(())
}
/// 获取全局数据库连接池
pub fn get_db() -> Result<Pool<Postgres>, AppError> {
    let global_db = GLOBAL_DB.get()
        .ok_or_else(|| AppError::DatabaseError("数据库未初始化，请先调用 init()".to_string()))?;
    
    let db_guard = global_db.read();
    db_guard
        .as_ref()
        .cloned()
        .ok_or_else(|| AppError::DatabaseError("数据库连接池未初始化".to_string()))
}

/// 执行原始SQL查询
pub async fn execute(sql: &str) -> Result<u64, AppError> {
    let pool = get_db()?;
    sqlx::query(sql)
        .execute(&pool)
        .await
        .map(|result| result.rows_affected())
        .map_err(AppError::from)
}
/// 构建查询
pub fn query<T: crate::model::Model>() -> crate::query::QueryBuilder<T> {
    let pool = get_db().expect("数据库未初始化，请先调用 init()");
    crate::query::QueryBuilder::new(pool)
}



/// 健康检查
pub async fn health_check() -> Result<bool, AppError> {
    let pool = get_db()?;
    
    match sqlx::query("SELECT 1").execute(&pool).await {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::error!("数据库健康检查失败: {}", e);
            Ok(false)
        }
    }
}
/// 关闭数据库连接池
pub async fn close() -> Result<(), AppError> {
    let global_db = GLOBAL_DB.get()
        .ok_or_else(|| AppError::DatabaseError("数据库未初始化".to_string()))?;
    
    let mut db_guard = global_db.write();
    if let Some(pool) = db_guard.take() {
        pool.close().await;
        tracing::info!("数据库连接池已关闭");
    }
    
    Ok(())
}
/// 获取模型实例
pub fn model<T: crate::model::Model>() -> T {
    T::default()
}
