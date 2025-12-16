use validator::Validate;
use tracing::{info, warn, error};
use crate::{AppConfig, ConfigError, ConfigResult, DEFAULT_RUN_MODE, RUN_MODE_ENV};

/// 配置验证器
#[derive(Debug, Clone)]
pub struct ConfigValidator;

impl ConfigValidator {
    /// 创建新的验证器
    pub fn new() -> Self {
        Self
    }
    
    /// 验证配置
    pub fn validate(&self, config: &AppConfig) -> ConfigResult<()> {
        info!("正在验证配置...");
        
        // 验证主配置
        config.validate()
            .map_err(|e| ConfigError::ValidationFailed(format!("主配置验证失败: {}", e)))?;
        
        // 验证各个子配置
        self.validate_server_config(&config.server)?;
        self.validate_database_config(&config.database)?;
        self.validate_redis_config(&config.redis)?;
        self.validate_jwt_config(&config.jwt)?;
        self.validate_video_config(&config.video)?;
        self.validate_payment_config(&config.payment)?;
        
        // 验证环境特定的规则
        self.validate_environment_specific(config)?;
        
        // 验证配置一致性
        self.validate_consistency(config)?;
        
        info!("配置验证通过");
        Ok(())
    }
    
    /// 验证服务器配置
    fn validate_server_config(&self, config: &crate::ServerConfig) -> ConfigResult<()> {
        // HTTPS验证
        if config.enable_https {
            if config.tls_cert_path.is_none() || config.tls_key_path.is_none() {
                return Err(ConfigError::ValidationFailed(
                    "已启用 HTTPS，但未指定 TLS 证书或密钥路径".to_string()
                ));
            }
            
            // 检查证书文件是否存在
            if let Some(cert_path) = &config.tls_cert_path {
                if !std::path::Path::new(cert_path).exists() {
                    warn!("未找到 TLS 证书文件: {}", cert_path);
                }
            }
            
            if let Some(key_path) = &config.tls_key_path {
                if !std::path::Path::new(key_path).exists() {
                    warn!("未找到 TLS 密钥文件: {}", key_path);
                }
            }
        }
        
        Ok(())
    }
    
    /// 验证数据库配置
    fn validate_database_config(&self, config: &crate::DatabaseConfig) -> ConfigResult<()> {
        // 验证连接池配置
        if config.max_connections < config.min_connections {
            return Err(ConfigError::ValidationFailed(
                format!("max_connections ({}) 必须 >= min_connections ({})", 
                        config.max_connections, config.min_connections)
            ));
        }
        
        // 验证SSL配置
        if config.enable_ssl {
            if config.ssl_ca_cert_path.is_none() {
                warn!("数据库连接已启用 SSL，但未指定 CA 证书路径");
            }
        }
        
        Ok(())
    }
    
    /// 验证Redis配置
    fn validate_redis_config(&self, config: &crate::RedisConfig) -> ConfigResult<()> {
        // 验证集群和哨兵模式互斥
        if config.cluster_mode && config.sentinel_mode {
            return Err(ConfigError::ValidationFailed(
                "Redis不能同时处于集群模式和哨兵模式".to_string()
            ));
        }
        
        // 验证哨兵模式配置
        if config.sentinel_mode {
            if config.sentinel_master_name.is_none() {
                return Err(ConfigError::ValidationFailed(
                    "Redis哨兵模式需要 sentinel_master_name".to_string()
                ));
            }
            
            if config.sentinel_nodes.is_empty() {
                return Err(ConfigError::ValidationFailed(
                    "Redis哨兵模式至少需要一个哨兵节点".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// 验证JWT配置
    fn validate_jwt_config(&self, config: &crate::JwtConfig) -> ConfigResult<()> {
        // 验证密钥长度
        if config.secret.len() < 32 {
            warn!("JWT 秘密太短（{} 字符），建议最少为 32 字符", 
                  config.secret.len());
        }
        
        // 验证算法
        let valid_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", 
                               "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"];
        if !valid_algorithms.contains(&config.algorithm.as_str()) {
            return Err(ConfigError::ValidationFailed(
                format!("无效的 JWT 算法：{}，有效选项为： {:?}", 
                        config.algorithm, valid_algorithms)
            ));
        }
        
        Ok(())
    }
    
    /// 验证视频配置
    fn validate_video_config(&self, config: &crate::VideoConfig) -> ConfigResult<()> {
        // 验证转码配置
        for profile in &config.transcoding_profiles {
            if profile.width % 2 != 0 || profile.height % 2 != 0 {
                return Err(ConfigError::ValidationFailed(
                    format!("视频尺寸必须是 numbers: {}x{}", 
                            profile.width, profile.height)
                ));
            }
            
            if profile.width > 7680 || profile.height > 4320 {
                warn!("视频分辨率 {}x{} 超过常见限制", 
                      profile.width, profile.height);
            }
        }
        
        // 验证水印配置
        if config.watermark_enabled && config.watermark_path.is_none() {
            return Err(ConfigError::ValidationFailed(
                "已启用水印，但未指定水印路径".to_string()
            ));
        }
        
        // 验证DRM配置
        if config.enable_drm {
            let valid_providers = ["widevine", "playready", "fairplay", "clearkey"];
            if !valid_providers.contains(&config.drm_provider.to_lowercase().as_str()) {
                return Err(ConfigError::ValidationFailed(
                    format!("无效的 DRM 提供者：{}，有效选项为: {:?}", 
                            config.drm_provider, valid_providers)
                ));
            }
        }
        
        Ok(())
    }
    
    /// 验证支付配置
    fn validate_payment_config(&self, config: &crate::PaymentConfig) -> ConfigResult<()> {
        // 验证货币代码
        let currency_regex = regex::Regex::new(r"^[A-Z]{3}$").unwrap();
        if !currency_regex.is_match(&config.default_currency) {
            return Err(ConfigError::ValidationFailed(
                format!("无效的货币代码：{}，必须是3个大写字母", 
                        config.default_currency)
            ));
        }
        
        // 验证手续费率
        if config.platform_fee_rate < 0.0 || config.platform_fee_rate > 100.0 {
            return Err(ConfigError::ValidationFailed(
                format!("平台费用率必须在0到100之间: {}", 
                        config.platform_fee_rate)
            ));
        }
        
        // 验证提现金额
        if config.min_withdrawal_amount > config.max_withdrawal_amount {
            return Err(ConfigError::ValidationFailed(
                format!("min_withdrawal_amount ({}) 必须 <= max_withdrawal_amount ({})", 
                        config.min_withdrawal_amount, config.max_withdrawal_amount)
            ));
        }
        
        // 验证支付渠道
        for (channel_name, channel_config) in &config.channels {
            if channel_config.enabled {
                if channel_config.fee_rate < 0.0 || channel_config.fee_rate > 100.0 {
                    return Err(ConfigError::ValidationFailed(
                        format!("支付渠道 {} 的费率必须在 0 到 100 之间: {}", 
                                channel_name, channel_config.fee_rate)
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// 验证环境特定的规则
    fn validate_environment_specific(&self, config: &AppConfig) -> ConfigResult<()> {
        // 开发环境警告
        if std::env::var(RUN_MODE_ENV).unwrap_or_default() == DEFAULT_RUN_MODE {
            // 开发环境使用弱密码警告
            if config.jwt.secret == "your-super-secret-jwt-key-change-in-production" {
                warn!("在开发模式下使用默认的 JWT 密钥");
            }
            
            if config.encryption.key == base64::encode(vec![0u8; 32]) {
                warn!("在开发模式中使用默认加密密钥");
            }
        }
        
        // 生产环境检查
        if std::env::var(RUN_MODE_ENV).unwrap_or_default() == "production" {
            // 生产环境必须使用HTTPS
            if !config.server.enable_https {
                return Err(ConfigError::ValidationFailed(
                    "生产环境中必须启用 HTTPS".to_string()
                ));
            }
            
            // 生产环境必须使用安全的JWT密钥
            if config.jwt.secret.len() < 64 {
                return Err(ConfigError::ValidationFailed(
                    "在生产环境中，JWT 密钥必须至少为 64 个字符".to_string()
                ));
            }
            
            // 生产环境必须配置数据库SSL
            if !config.database.enable_ssl {
                warn!("生产环境中未启用数据库 SSL");
            }
        }
        
        Ok(())
    }
    
    /// 验证配置一致性
    fn validate_consistency(&self, config: &AppConfig) -> ConfigResult<()> {
        // 检查存储配置一致性
        if config.storage.enable_multi_storage {
            let enabled_providers = vec![
                config.storage.local.enabled,
                config.storage.s3.enabled,
            ];
            
            let enabled_count = enabled_providers.iter().filter(|&&enabled| enabled).count();
            if enabled_count < 2 {
                warn!("多存储已启用，但启用的存储提供商少于 2 个");
            }
        }
        
        // 检查缓存配置一致性
        if config.cache.enabled {
            if !config.cache.enable_memory && !config.cache.enable_redis {
                warn!("已启用缓存，但未启用缓存后端");
            }
        }
        
        // 检查队列配置一致性
        if config.queue.enabled {
            let enabled_providers = vec![
                config.queue.redis.enabled,
                config.queue.rabbitmq.enabled,
                config.queue.sqs.enabled,
            ];
            
            let enabled_count = enabled_providers.iter().filter(|&&enabled| enabled).count();
            if enabled_count == 0 {
                return Err(ConfigError::ValidationFailed(
                    "Queue队列已启用，但未启用队列提供程序".to_string()
                ));
            }
            
            if enabled_count > 1 {
                warn!("启用了多个队列提供程序，但只会使用一个");
            }
        }
        
        // 检查监控配置一致性
        if config.telemetry.enabled {
            if config.telemetry.endpoint.is_empty() {
                warn!("Telemetry 已启用遥测，但终端为空");
            }
        }
        
        Ok(())
    }
    
    /// 验证配置文件的语法
    pub fn validate_syntax(content: &str) -> ConfigResult<()> {
        toml::from_str::<AppConfig>(content)
            .map_err(|e| ConfigError::ValidationFailed(format!("配置语法无效: {}", e)))?;
        
        Ok(())
    }
    
    /// 验证配置文件路径
    pub fn validate_file_path(path: &str) -> ConfigResult<()> {
        let path = std::path::Path::new(path);
        
        if !path.exists() {
            return Err(ConfigError::ValidationFailed(
                format!("配置文件不存在: {:?}", path)
            ));
        }
        
        if !path.is_file() {
            return Err(ConfigError::ValidationFailed(
                format!("路径不是文件: {:?}", path)
            ));
        }
        
        // 检查文件扩展名
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");
        
        if !["toml", "json", "yaml", "yml"].contains(&extension) {
            warn!("配置文件的扩展名不正常: .{}", extension);
        }
        
        Ok(())
    }
    
    /// 生成配置验证报告
    pub fn generate_validation_report(config: &AppConfig) -> ValidationReport {
        let mut report = ValidationReport::new();
        
        // 检查关键配置项
        if config.jwt.secret.len() < 32 {
            report.add_warning("JWT 密钥太短".to_string());
        }
        
        if config.encryption.key == base64::encode(vec![0u8; 32]) {
            report.add_warning("使用默认加密密钥".to_string());
        }
        
        if !config.server.enable_https {
            report.add_warning("未启用 HTTPS".to_string());
        }
        
        // 检查推荐配置
        if config.server.worker_threads < 2 {
            report.add_warning("工作线程少于2".to_string());
        }
        
        if config.database.max_connections < 10 {
            report.add_warning("数据库最大连接数少于10".to_string());
        }
        
        if config.redis.pool_size < 5 {
            report.add_warning("Redis 池大小小于 5".to_string());
        }
        
        // 检查特性配置
        if config.features.enable_registration && !config.features.enable_email_verification {
            report.add_warning("已启用注册，但未启用电子邮件验证".to_string());
        }
        
        report
    }
}

impl Default for ConfigValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// 验证报告
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub passed: bool,
}

impl ValidationReport {
    /// 创建新的验证报告
    pub fn new() -> Self {
        Self {
            warnings: Vec::new(),
            errors: Vec::new(),
            passed: true,
        }
    }
    
    /// 添加警告
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
    
    /// 添加错误
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
        self.passed = false;
    }
    
    /// 检查是否通过
    pub fn is_passed(&self) -> bool {
        self.passed && self.errors.is_empty()
    }
    
    /// 获取报告摘要
    pub fn summary(&self) -> String {
        format!("验证 {}：{} 警告，{} 错误",
                if self.is_passed() { "passed" } else { "failed" },
                self.warnings.len(),
                self.errors.len())
    }
    
    /// 生成详细报告
    pub fn generate_detailed_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str(&format!("验证报告t\n"));
        report.push_str(&format!("================\n\n"));
        report.push_str(&format!("状态: {}\n\n", 
            if self.is_passed() { "PASSED" } else { "FAILED" }));
        
        if !self.errors.is_empty() {
            report.push_str("错误:\n");
            for error in &self.errors {
                report.push_str(&format!("  - {}\n", error));
            }
            report.push_str("\n");
        }
        
        if !self.warnings.is_empty() {
            report.push_str("警告:\n");
            for warning in &self.warnings {
                report.push_str(&format!("  - {}\n", warning));
            }
            report.push_str("\n");
        }
        
        report.push_str(&format!("总计：{} 个错误，{} 个警告\n", 
            self.errors.len(), self.warnings.len()));
        
        report
    }
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self::new()
    }
}

/// 便捷函数：验证配置
pub fn validate_config(config: &AppConfig) -> ConfigResult<ValidationReport> {
    let validator = ConfigValidator::new();
    
    match validator.validate(config) {
        Ok(_) => {
            let report = ConfigValidator::generate_validation_report(config);
            if !report.is_passed() {
                warn!("配置验证已完成，但有警告: {}", report.summary());
            } else {
                info!("配置验证通过: {}", report.summary());
            }
            Ok(report)
        }
        Err(e) => {
            error!("配置验证失败: {}", e);
            let mut report = ValidationReport::new();
            report.add_error(e.to_string());
            Err(ConfigError::ValidationFailed(format!("配置验证失败: {}", e)))
        }
    }
}

/// 便捷函数：验证配置文件
pub fn validate_config_file(path: &str) -> ConfigResult<ValidationReport> {
    // 验证文件路径
    ConfigValidator::validate_file_path(path)?;
    
    // 读取文件内容
    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::IoError(format!("读取配置文件失败: {}", e)))?;
    
    // 验证语法
    ConfigValidator::validate_syntax(&content)?;
    
    // 加载配置
    let config: AppConfig = toml::from_str(&content)
        .map_err(|e| ConfigError::DeserializationFailed(format!("配置反序列化失败: {}", e)))?;
    
    // 验证配置
    validate_config(&config)
}