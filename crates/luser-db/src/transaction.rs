//! 事务管理模块

use std::sync::Arc;
use tokio::sync::Mutex;
use sqlx::{Pool, Postgres, Transaction};
use luser_common::AppError;

/// 事务管理器
#[derive(Debug, Clone)]
pub struct TransactionManager {
    pool: Pool<Postgres>,
}

impl TransactionManager {
    /// 创建新的事务管理器
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
    
    /// 开始事务
    pub async fn begin(&self) -> Result<Transaction<'_, Postgres>, AppError> {
        self.pool
            .begin()
            .await
            .map_err(AppError::from)
    }
    
    /// 执行事务
    pub async fn execute<F, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut Transaction<'_, Postgres>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, AppError>> + Send>>,
    {
        let mut tx = self.begin().await?;
        
        match f(&mut tx).await {
            Ok(result) => {
                tx.commit().await.map_err(AppError::from)?;
                Ok(result)
            }
            Err(e) => {
                tx.rollback().await.map_err(AppError::from)?;
                Err(e)
            }
        }
    }
}

/// 事务上下文
pub struct TransactionContext {
    transaction: Mutex<Option<Transaction<'static, Postgres>>>,
}

impl TransactionContext {
    /// 创建新的事务上下文
    pub fn new() -> Self {
        Self {
            transaction: Mutex::new(None),
        }
    }
    
    /// 开始事务
    pub async fn begin(&self) -> Result<(), AppError> {
        let mut tx_guard = self.transaction.lock().await;
        
        if tx_guard.is_some() {
            return Err(AppError::DatabaseError("事务已开始".to_string()));
        }
        
        let pool = crate::global::get_db()?;
        let tx = pool.begin().await.map_err(AppError::from)?;
        
        // 安全转换：我们知道事务生命周期会被管理
        let tx = unsafe {
            std::mem::transmute::<Transaction<'_, Postgres>, Transaction<'static, Postgres>>(tx)
        };
        
        *tx_guard = Some(tx);
        Ok(())
    }
    
    /// 提交事务
    pub async fn commit(&self) -> Result<(), AppError> {
        let mut tx_guard = self.transaction.lock().await;
        
        if let Some(tx) = tx_guard.take() {
            tx.commit().await.map_err(AppError::from)?;
            Ok(())
        } else {
            Err(AppError::DatabaseError("没有事务可以提交".to_string()))
        }
    }
    
    /// 回滚事务
    pub async fn rollback(&self) -> Result<(), AppError> {
        let mut tx_guard = self.transaction.lock().await;
        
        if let Some(tx) = tx_guard.take() {
            tx.rollback().await.map_err(AppError::from)?;
            Ok(())
        } else {
            Err(AppError::DatabaseError("没有事务可以回滚".to_string()))
        }
    }
    
    /// 检查是否在事务中
    pub async fn in_transaction(&self) -> bool {
        let tx_guard = self.transaction.lock().await;
        tx_guard.is_some()
    }
}

/// 全局事务管理器
pub fn transaction_manager() -> Result<TransactionManager, AppError> {
    let pool = crate::global::get_db()?;
    Ok(TransactionManager::new(pool))
}

/// 执行事务的便捷函数
pub async fn execute_transaction<F, T>(f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut Transaction<'_, Postgres>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, AppError>> + Send>>,
{
    let manager = transaction_manager()?;
    manager.execute(f).await
}

/// 事务宏
#[macro_export]
macro_rules! transaction {
    ($code:block) => {
        {
            use $crate::transaction::execute_transaction;
            
            execute_transaction(|tx| {
                Box::pin(async move {
                    $code
                })
            }).await
        }
    };
}