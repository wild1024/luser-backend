

## 完整的应用创建示例

```rust
use crate::config::{ConfigManager, init_global_config, get_global_config};

/// 应用配置管理器
pub struct Application {
    config_manager: ConfigManager,
}

impl Application {
    /// 创建应用（带完整的配置管理）
    pub async fn new_with_full_config() -> Result<Self, Box<dyn std::error::Error>> {
        // 1. 设置加密密钥
        std::env::set_var(
            "LUSER_ENCRYPTION_KEY",
            EncryptionManager::generate_base64_key(EncryptionAlgorithm::Aes256Gcm)?,
        );
        
        // 2. 创建带密钥管理的配置管理器（密钥每30天轮换一次）
        let rotation_interval = std::time::Duration::from_secs(30 * 24 * 60 * 60);
        let config_manager = ConfigManager::new_with_key_management(Some(rotation_interval))?;
        
        // 3. 启动配置文件监控（每5秒检查一次）
        config_manager.start_watching()?;
        
        // 4. 启动数据库配置监控（每分钟检查一次）
        let db_check_interval = Duration::from_secs(60);
        config_manager.start_database_watching(db_check_interval)?;
        
        // 5. 启动自动重载任务（每30秒检查一次）
        let auto_reload_interval = Duration::from_secs(30);
        config_manager.start_auto_reload_task(auto_reload_interval).await?;
        
        Ok(Self { config_manager })
    }
    
    /// 启动应用
    pub async fn run(&self) {
        info!("Starting application with full configuration management");
        
        // 获取当前配置
        let config = self.config_manager.get_config();
        
        // 启动服务...
        info!("Server starting on: {}", config.server_addr());
        
        // 监控配置变化
        self.monitor_config_changes().await;
    }
    
    /// 监控配置变化
    async fn monitor_config_changes(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        
        loop {
            interval.tick().await;
            
            // 检查配置更新历史
            let updates = self.config_manager.get_dynamic_update_history(5);
            if !updates.is_empty() {
                info!("Recent configuration updates:");
                for update in updates {
                    info!("  [{}] {}: {}", 
                        update.timestamp.format("%H:%M:%S"),
                        update.source,
                        update.description
                    );
                }
            }
            
            // 检查是否需要轮换密钥
            if let Some(encryptor) = self.config_manager.encryptor() {
                if let Some(key_manager) = encryptor.key_manager() {
                    if key_manager.read().should_rotate_key() {
                        if let Ok(new_key_id) = self.config_manager.rotate_key() {
                            info!("Key automatically rotated: {}", new_key_id);
                        }
                    }
                }
            }
        }
    }
    
    /// 导出当前配置
    pub fn export_current_config(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.config_manager.export_to_file(path)?;
        info!("Current configuration exported to: {}", path);
        Ok(())
    }
    
    /// 更新配置值
    pub fn update_config_value(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.config_manager.update_config_value(key, value)?;
        info!("Configuration updated: {} = {}", key, value);
        Ok(())
    }
    
    /// 获取配置摘要
    pub fn get_config_summary(&self) -> String {
        let config = self.config_manager.get_config();
        let sources = self.config_manager.get_source_info();
        let priority_summary = self.config_manager.get_priority_summary();
        
        format!(
            "Configuration Summary:\n\
            - Server: {}:{}\n\
            - Environment: {}\n\
            - Sources: {}\n\
            - Priority distribution: {:?}",
            config.server.host,
            config.server.port,
            config.server.environment,
            sources.len(),
            priority_summary
        )
    }
}

// 全局配置管理器使用示例
pub async fn initialize_application() -> Result<(), Box<dyn std::error::Error>> {
    // 方法1：使用全局配置管理器
    init_global_config()?;
    let global_config = get_global_config()?;
    
    // 启动监控
    global_config.start_watching()?;
    
    // 方法2：创建自定义应用
    let app = Application::new_with_full_config().await?;
    app.run().await;
    
    // 导出加密的配置文件
    app.export_current_config("config.encrypted.toml")?;
    
    // 更新配置示例
    app.update_config_value("server.port", "8081")?;
    
    Ok(())
}

// 主函数示例
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    info!("Starting application with advanced configuration management");
    
    // 创建并启动应用
    let app = Application::new_with_full_config().await?;
    
    // 打印配置摘要
    println!("{}", app.get_config_summary());
    
    // 启动应用
    app.run().await;
    
    Ok(())
}
```

## 关键功能说明：

1. **配置监控**：
   - 文件系统监控：自动检测配置文件变化并重新加载
   - 数据库配置监控：定期检查数据库中的配置更新
   - 自动重载任务：定期检查配置是否需要重新加载

2. **加密集成**：
   - 自动加密/解密敏感配置
   - 密钥轮换管理
   - 支持多种加密算法

3. **动态更新**：
   - 支持运行时更新配置
   - 记录配置变更历史
   - 支持批量更新和单个值更新

4. **配置合并**：
   - 支持多源配置合并
   - 优先级管理
   - 深度合并策略

5. **验证和验证**：
   - 配置验证
   - 加密完整性检查
   - 安全级别管理

这个完整的 `ConfigManager` 实现提供了企业级的配置管理功能，包括监控、加密、动态更新和验证等功能。