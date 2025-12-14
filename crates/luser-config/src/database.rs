use sqlx::postgres::PgPool;
use crate::ConfigError;
use tracing::info;

pub async fn setup_config_table(pool: &PgPool) -> Result<(), ConfigError> {
    // 创建配置表
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS configurations (
            id SERIAL PRIMARY KEY,
            key VARCHAR(255) NOT NULL,
            value TEXT NOT NULL,
            environment VARCHAR(50) NOT NULL DEFAULT 'all',
            description TEXT,
            encrypted BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(key, environment)
        )
        "#
    )
    .execute(pool)
    .await
    .map_err(|e| ConfigError::LoadFailed(format!("Failed to load database config: {}", e)))?;
    
    // 创建索引
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_configurations_environment ON configurations(environment)"
    )
    .execute(pool)
    .await
    .map_err(|e| ConfigError::LoadFailed(format!("Failed to load database config: {}", e)))?;
    
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_configurations_key ON configurations(key)"
    )
    .execute(pool)
    .await
    .map_err(|e| ConfigError::LoadFailed(format!("Failed to load database config: {}", e)))?;
    
    info!("Configuration table setup completed");
    Ok(())
}

pub async fn insert_default_configs(pool: &PgPool, environment: &str) -> Result<(), ConfigError> {
    let default_configs = vec![
        ("server.request_timeout", "30", "Request timeout in seconds"),
        ("server.max_body_size", "10", "Max request body size in MB"),
        ("jwt.expiration_hours", "24", "JWT token expiration hours"),
        ("video.max_file_size_mb", "2048", "Max video file size in MB"),
        ("rate-limit.enabled", "true", "Enable rate limiting"),
        ("rate-limit.global_limit", "1000", "Global rate limit per minute"),
        ("rate-limit.ip_limit", "100", "IP rate limit per minute"),
        ("rate-limit.user_limit", "500", "User rate limit per minute"),
        ("telemetry.enabled", "true", "Enable telemetry collection"),
        ("telemetry.sampling_rate", "0.1", "Telemetry sampling rate"),
        ("cache.enabled", "true", "Enable caching"),
        ("cache.default_ttl", "3600", "Default cache TTL in seconds"),
        ("queue.enabled", "true", "Enable task queue"),
        ("queue.max_workers", "10", "Maximum number of queue workers"),
        ("task.video-transcode.enabled", "true", "Enable video transcoding task"),
        ("task.video-transcode.max_concurrent", "5", "Max concurrent video transcodes"),
    ];
    
    for (key, value, description) in &default_configs {
        sqlx::query(
            "INSERT INTO configurations (key, value, environment, description)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (key, environment) DO NOTHING"
        )
        .bind(key)
        .bind(value)
        .bind(environment)
        .bind(description)
        .execute(pool)
        .await
        .map_err(|e| ConfigError::LoadFailed(format!("Failed to load database config: {}", e)))?;
    }
    
    info!("Inserted {} default configurations for environment: {}", 
          default_configs.len(), environment);
    Ok(())
}

// 清理旧的配置记录
pub async fn cleanup_old_configs(pool: &PgPool, retention_days: i32) -> Result<u64, ConfigError> {
    let result = sqlx::query(
        "DELETE FROM configurations 
         WHERE updated_at < CURRENT_TIMESTAMP - INTERVAL '1 day' * $1
         AND environment NOT IN ('all', 'default')"
    )
    .bind(retention_days)
    .execute(pool)
    .await
    .map_err(|e| ConfigError::LoadFailed(format!("Failed to load database config: {}", e)))?;
    
    info!("Cleaned up {} old configuration records", result.rows_affected());
    Ok(result.rows_affected())
}