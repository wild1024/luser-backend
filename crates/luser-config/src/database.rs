use std::collections::HashMap;

use crate::{AppConfig, ConfigError, ConfigResult, ConfigSecurityLevel, get_global_encryptor};
use chrono::Utc;
use sqlx::{Pool, Postgres, Row};
use tracing::{debug, error, info};
use base64::{Engine, engine::general_purpose::STANDARD};
#[derive(Debug, Clone)]
pub struct DatabaseConfigRecord {
    pub config_key: String,
    pub config_value: String,
    pub config_type: String,
    pub environment: String,
    pub priority: i32,
    pub updated_at: chrono::DateTime<Utc>,
}

pub struct DatabaseConfigLoader;

impl DatabaseConfigLoader {
    /// 从数据库加载配置
    pub async fn load_config_from_db(
        pool: &Pool<Postgres>,
        environment: &str,
    ) -> Result<Option<HashMap<String, String>>, ConfigError> {
        let result = sqlx::query(
            r#"
            SELECT 
                config_key, 
                config_value, 
                config_type, 
                environment, 
                priority,
                updated_at
            FROM configurations
            WHERE (environment = $1 OR environment = 'default')
            AND is_active = true
            ORDER BY 
                CASE environment 
                    WHEN $1 THEN 1 
                    WHEN 'default' THEN 2 
                    ELSE 3 
                END,
                priority DESC
            "#,
        )
        .bind(environment)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            ConfigError::DatabaseError(format!("加载数据库配置失败: {}", e))
        })?;

        if result.is_empty() {
            return Ok(None);
        }

        // 记录调试信息
        debug!("已从数据库加载 {} 条配置记录", result.len());

        // 转换为配置映射
        let mut config_map = HashMap::new();
        let mut records = Vec::new();

        for row in result {
            let record = DatabaseConfigRecord {
                config_key: row.get("config_key"),
                config_value: row.get("config_value"),
                config_type: row.get("config_type"),
                environment: row.get("environment"),
                priority: row.get("priority"),
                updated_at: row.get("updated_at"),
            };
            records.push(record);
        }

        // 处理配置值，按优先级和环境覆盖
        Self::process_config_records(&records, &mut config_map, environment);

        Ok(Some(config_map))
    }
   /// 处理配置记录，处理覆盖逻辑
    fn process_config_records(
        records: &[DatabaseConfigRecord],
        config_map: &mut HashMap<String, String>,
        target_environment: &str,
    ) {
        // 按优先级排序（环境特定优先于default）
        for record in records {
            // 如果已经存在同键的环境特定配置，跳过默认环境的低优先级配置
            if record.environment == "default" {
                if let Some(existing) = config_map.get(&record.config_key) {
                    // 如果已经有环境特定的配置，跳过默认配置
                    continue;
                }
            }

            config_map.insert(record.config_key.clone(), record.config_value.clone());
        }
    }
    /// 检查数据库配置是否有更新
    pub async fn check_config_updated(
        pool: &Pool<Postgres>,
        environment: &str,
        last_check: chrono::DateTime<Utc>,
    ) -> Result<bool, ConfigError> {
        let result = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM configurations
                WHERE (environment = $1 OR environment = 'default')
                AND is_active = true
                AND updated_at > $2
            )
            "#,
        )
        .bind(environment)
        .bind(last_check)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            ConfigError::DatabaseError(format!("检查配置更新失败: {}", e))
        })?;

        Ok(result)
    }

    /// 初始化配置表
    pub async fn initialize_config_table(
        &self,
        pool: &Pool<Postgres>,
        force_reinit: bool,
    ) -> ConfigResult<()> {
        info!("初始化配置表");

        // 检查配置表是否存在
        let table_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'configurations'
            )
            "#,
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            crate::error::ConfigError::DatabaseError(format!("检查配置表失败: {}", e))
        })?;

        if !table_exists || force_reinit {
            info!("创建配置表");

            // 创建配置表（使用 database.rs 中的表结构）
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS configurations (
                    id SERIAL PRIMARY KEY,
                    config_key VARCHAR(255) NOT NULL,
                    config_value TEXT NOT NULL,
                    config_type VARCHAR(50) NOT NULL,
                    environment VARCHAR(50) NOT NULL,
                    priority INTEGER DEFAULT 100,
                    is_active BOOLEAN DEFAULT true,
                    encrypted BOOLEAN DEFAULT FALSE,
                    description TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(config_key, environment)
                )
                "#,
            )
            .execute(pool)
            .await
            .map_err(|e| {
                crate::error::ConfigError::DatabaseError(format!(
                    "创建配置表失败: {}",
                    e
                ))
            })?;

            // 创建索引
            sqlx::query(
                r#"
                CREATE INDEX IF NOT EXISTS idx_configurations_key_env 
                ON configurations(config_key, environment, is_active)
                "#,
            )
            .execute(pool)
            .await
            .map_err(|e| {
                crate::error::ConfigError::DatabaseError(format!("创建索引失败: {}", e))
            })?;

            info!("配置表创建成功");
        } else {
            info!("配置表已存在");
        }

        Ok(())
    }
    /// 测试配置系统是否已初始化
    pub async fn is_config_system_initialized(pool: &Pool<Postgres>) -> ConfigResult<bool> {
        let result: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM configurations 
                WHERE config_key = 'full_config' 
                AND is_active = true
            )
        "#,
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            crate::error::ConfigError::DatabaseError(format!(
                "初始化检查失败: {}",
                e
            ))
        })?;

        Ok(result.0)
    }
    /// 检查配置表是否存在且有数据
    pub async fn has_database_config(
         &self,
        pool: &Pool<Postgres>,
        environment: &str,
    ) -> ConfigResult<bool> {
        info!("检查数据库配置是否存在，环境: {}", environment);
        
        // 检查表是否存在
        let table_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'configurations'
            )
            "#,
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            ConfigError::DatabaseError(format!("检查配置表失败: {}", e))
        })?;
        
        if !table_exists {
            return Ok(false);
        }
        
        // 检查是否有该环境的配置
        let has_config: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM configurations 
                WHERE environment = $1 
                AND is_active = true
            )
            "#,
        )
        .bind(environment)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            ConfigError::DatabaseError(format!("检查数据库配置失败: {}", e))
        })?;
        
        Ok(has_config)
    }
    
    /// 同步本地配置到数据库（加密存储）
    pub async fn sync_local_config_to_database(
        &self,
        pool: &Pool<Postgres>,
        env: &str,
        config: &AppConfig,
    ) -> ConfigResult<()> {
        info!("同步本地配置到数据库，环境: {}", env);
        
        // 1. 确保配置表存在
        self.initialize_config_table(pool, true).await?;
        
        // 2. 获取加密器
        let encryptor = get_global_encryptor()?;
        
        // 3. 加密整个配置
        let mut encrypted_config = config.clone();
        encryptor.encrypt_config(&mut encrypted_config)?;
        
        // 4. 将配置转换为TOML字符串
        let toml_config = toml::to_string(&encrypted_config)
            .map_err(|e| ConfigError::SerializationFailed(format!("配置序列化失败: {}", e)))?;
        
        // 5. 保存到数据库
        sqlx::query(
            r#"
            INSERT INTO configurations 
            (config_key, config_value, config_type, environment, priority, encrypted, description)
            VALUES 
            ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (config_key, environment) 
            DO UPDATE SET 
                config_value = EXCLUDED.config_value,
                updated_at = CURRENT_TIMESTAMP,
                encrypted = EXCLUDED.encrypted
            "#,
        )
        .bind("full_config")
        .bind(&toml_config)
        .bind("toml")
        .bind(env)
        .bind(999) // 最高优先级
        .bind(true)
        .bind("完整的应用程序配置")
        .execute(pool)
        .await
        .map_err(|e| ConfigError::DatabaseError(format!("保存配置到数据库失败: {}", e)))?;
        
        info!("本地配置已同步到数据库");
        Ok(())
    }
    /// 重置配置系统（开发/测试用）
    pub async fn reset_config_system(pool: &Pool<Postgres>, environment: &str) -> ConfigResult<()> {
        info!(
            "重置环境系统配置: {}",
            environment
        );

        // 删除所有配置
        sqlx::query("DELETE FROM configurations WHERE environment = $1")
            .bind(environment)
            .execute(pool)
            .await
            .map_err(|e| {
                crate::error::ConfigError::DatabaseError(format!(
                    "重置系统配置失败: {}",
                    e
                ))
            })?;

        info!("系统配置重置成功");
        Ok(())
    }
     /// 重新加密数据库中的所有配置（密钥轮换后调用）
    pub async fn reencrypt_database_configs(pool: &Pool<Postgres>) -> ConfigResult<()> {
        info!("开始重新加密数据库配置（密钥轮换后）");
        
        // 获取所有加密的配置
        let records = sqlx::query(
            r#"
            SELECT config_key, config_value, environment
            FROM configurations
            WHERE encrypted = true
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(|e| ConfigError::DatabaseError(format!("获取加密配置失败: {}", e)))?;
        
        let encryptor = get_global_encryptor()?;
        
        // 重新加密每个配置
        for record in records {
            let config_key: String = record.get("config_key");
            let config_value: String = record.get("config_value");
            let environment: String = record.get("environment");
            
            // 尝试使用历史密钥解密
            let decrypted_value = if let Some(key_manager) = encryptor.key_manager() {
                // 使用历史密钥尝试解密
                let key_manager = key_manager.read();
                let encrypted_data = STANDARD.decode(&config_value)
                    .map_err(|e| ConfigError::EncryptionError(format!("解码base64失败: {}", e)))?;
                
                match key_manager.decrypt_with_historical_keys(&encrypted_data, &encryptor.encryption_manager()) {
                    Ok(decrypted_bytes) => String::from_utf8(decrypted_bytes)
                        .map_err(|e| ConfigError::EncryptionError(format!("解密数据转字符串失败: {}", e)))?,
                    Err(e) => {
                        error!("使用历史密钥解密失败 {}: {}", config_key, e);
                        continue;
                    }
                }
            } else {
                // 没有密钥管理器，使用当前密钥解密
                encryptor.decrypt_config_value(&config_key, &config_value)?
            };
            
            // 用新密钥重新加密
            let security_level = if config_key.contains("secret") || config_key.contains("key") {
                ConfigSecurityLevel::Secret
            } else {
                ConfigSecurityLevel::Sensitive
            };
            
            let reencrypted_value = encryptor.encrypt_config_value(
                &config_key,
                &decrypted_value,
                security_level,
            )?;
            
            // 更新数据库
            sqlx::query(
                r#"
                UPDATE configurations
                SET config_value = $1, updated_at = CURRENT_TIMESTAMP
                WHERE config_key = $2 AND environment = $3
                "#,
            )
            .bind(&reencrypted_value)
            .bind(&config_key)
            .bind(&environment)
            .execute(pool)
            .await
            .map_err(|e| ConfigError::DatabaseError(format!("更新配置失败 {}: {}", config_key, e)))?;
            
            debug!("配置已重新加密: {}", config_key);
        }
        
        info!("数据库配置重新加密完成");
        Ok(())
    }
    /// 根据配置创建数据库连接池
    pub async fn create_db_pool( &self, config: &AppConfig) -> ConfigResult<Pool<Postgres>> {
        info!("创建数据库连接池...");
        
        // 获取解密后的数据库URL
        let db_url = config.get_decrypted_database_url()?;
        
        info!("数据库URL: {}", mask_sensitive_url(&db_url));
        
        // 创建连接池
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .min_connections(config.database.min_connections)
            .acquire_timeout(std::time::Duration::from_secs(config.database.connection_timeout))
            .idle_timeout(std::time::Duration::from_secs(config.database.idle_timeout))
            .max_lifetime(std::time::Duration::from_secs(config.database.max_lifetime))
            .connect(&db_url)
            .await
            .map_err(|e| ConfigError::DatabaseError(format!("创建数据库连接池失败: {}", e)))?;
        
        info!("数据库连接池创建成功");
        Ok(pool)
    }
}
/// 隐藏敏感数据（用于日志）
fn mask_sensitive_url(input: &str) -> String {
    let patterns = vec![
        (r"([^:]+):([^@]+)@", r"$1:****@"),
    ];
    
    let mut result = input.to_string();
    for (pattern, replacement) in patterns {
        let re = regex::Regex::new(pattern).unwrap();
        result = re.replace_all(&result, replacement).to_string();
    }
    
    result
}