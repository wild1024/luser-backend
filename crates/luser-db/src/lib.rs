//! LUSER 数据库模块
//! 
//! 提供全局数据库管理、ActiveRecord模式、链式调用API

pub mod pool;
pub mod global;
pub mod model;
pub mod db;
pub mod query;
pub mod transaction;
pub mod migrator;


#[cfg(feature = "model-macros")]
pub mod macros;




// 重新导出常用类型
pub use model::{Model, BaseModel, BaseModelWithId};
pub use db::Db;
pub use query::QueryBuilder;
pub use transaction::{TransactionManager, execute_transaction};

// 重新导出公共错误类型
pub use luser_common::AppError;
pub use luser_common::Result;


/// 数据库初始化
pub async fn init_db() -> Result<()> {
     global::init_db().await
}



/// 便捷函数：查询构建
pub fn query<T: Model>() -> QueryBuilder<T> {
    global::query()
}

/// 便捷函数：获取模型实例
pub fn model<T: Model>() -> T {
    T::default()
}

/// 便捷函数：执行原始SQL
pub async fn execute_sql(sql: &str) -> Result<u64> {
    global::execute(sql).await
}
/// 便捷函数：获取Db实例
pub fn use_db<T: Model>() -> Db<T> {
    db::use_model()
}

/// 健康检查
pub async fn health_check() -> Result<bool> {
    global::health_check().await
}

/// 关闭数据库连接
pub async fn close() -> Result<()> {
    global::close().await
}