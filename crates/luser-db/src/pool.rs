//! 数据库连接池管理

//! 数据库初始化模块

use sqlx::{Pool, Postgres, postgres::{PgConnectOptions, PgPoolOptions}};
use luser_common::{AppError, mask_sensitive_data};
use tracing::info;



/// 创建数据库连接池
pub async fn create_pool( db_config: &luser_config::DatabaseConfig) -> Result<Pool<Postgres>, AppError> {
    info!("数据库URL: {}", mask_sensitive_data(&db_config.url));
    let pool_options = PgPoolOptions::new()
        .max_connections(db_config.max_connections)
        .min_connections(db_config.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(db_config.connection_timeout))
        .idle_timeout(std::time::Duration::from_secs(db_config.idle_timeout))
        .max_lifetime(std::time::Duration::from_secs(db_config.max_lifetime));
   
    pool_options
        .connect(&db_config.url)
        .await
        .map_err(|e| AppError::DatabaseError(format!("数据库连接失败: {}", e)))
}


/// 测试连接
pub async fn test_connection(url: &str) -> Result<bool, AppError> {
    let test_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .map_err(|e| AppError::DatabaseError(format!("测试连接失败: {}", e)))?;
    
    let result = sqlx::query("SELECT 1")
        .execute(&test_pool)
        .await
        .is_ok();
    
    test_pool.close().await;
    Ok(result)
}

