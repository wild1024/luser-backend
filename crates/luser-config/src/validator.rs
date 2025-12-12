use validator::Validate;
use tracing::{info, warn, error};
use crate::{AppConfig, ConfigResult, ConfigError};

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
        info!("Validating configuration...");
        
        // 验证主配置
        config.validate()
            .map_err(|e| ConfigError::ValidationFailed(format!("Main config validation failed: {}", e)))?;
        
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
        
        info!("Configuration validation passed");
        Ok(())
    }
    
    /// 验证服务器配置
    fn validate_server_config(&self, config: &crate::ServerConfig) -> ConfigResult<()> {
        // HTTPS验证
        if config.enable_https {
            if config.tls_cert_path.is_none() || config.tls_key_path.is_none() {
                return Err(ConfigError::ValidationFailed(
                    "HTTPS enabled but TLS certificate or key path not specified".to_string()
                ));
            }
            
            // 检查证书文件是否存在
            if let Some(cert_path) = &config.tls_cert_path {
                if !std::path::Path::new(cert_path).exists() {
                    warn!("TLS certificate file not found: {}", cert_path);
                }
            }
            
            if let Some(key_path) = &config.tls_key_path {
                if !std::path::Path::new(key_path).exists() {
                    warn!("TLS key file not found: {}", key_path);
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
                format!("max_connections ({}) must be >= min_connections ({})", 
                        config.max_connections, config.min_connections)
            ));
        }
        
        // 验证SSL配置
        if config.enable_ssl {
            if config.ssl_ca_cert_path.is_none() {
                warn!("SSL enabled but CA certificate path not specified");
            }
        }
        
        Ok(())
    }
    
    /// 验证Redis配置
    fn validate_redis_config(&self, config: &crate::RedisConfig) -> ConfigResult<()> {
        // 验证集群和哨兵模式互斥
        if config.cluster_mode && config.sentinel_mode {
            return Err(ConfigError::ValidationFailed(
                "Redis cannot be both cluster mode and sentinel mode".to_string()
            ));
        }
        
        // 验证哨兵模式配置
        if config.sentinel_mode {
            if config.sentinel_master_name.is_none() {
                return Err(ConfigError::ValidationFailed(
                    "Sentinel mode requires sentinel_master_name".to_string()
                ));
            }
            
            if config.sentinel_nodes.is_empty() {
                return Err(ConfigError::ValidationFailed(
                    "Sentinel mode requires at least one sentinel node".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// 验证JWT配置
    fn validate_jwt_config(&self, config: &crate::JwtConfig) -> ConfigResult<()> {
        // 验证密钥长度
        if config.secret.len() < 32 {
            warn!("JWT secret is too short ({} chars), recommended minimum is 32 chars", 
                  config.secret.len());
        }
        
        // 验证算法
        let valid_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", 
                               "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"];
        if !valid_algorithms.contains(&config.algorithm.as_str()) {
            return Err(ConfigError::ValidationFailed(
                format!("Invalid JWT algorithm: {}, valid options are: {:?}", 
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
                    format!("Video dimensions must be even numbers: {}x{}", 
                            profile.width, profile.height)
                ));
            }
            
            if profile.width > 7680 || profile.height > 4320 {
                warn!("Video resolution {}x{} exceeds common limits", 
                      profile.width, profile.height);
            }
        }
        
        // 验证水印配置
        if config.watermark_enabled && config.watermark_path.is_none() {
            return Err(ConfigError::ValidationFailed(
                "Watermark enabled but watermark path not specified".to_string()
            ));
        }
        
        // 验证DRM配置
        if config.enable_drm {
            let valid_providers = ["widevine", "playready", "fairplay", "clearkey"];
            if !valid_providers.contains(&config.drm_provider.to_lowercase().as_str()) {
                return Err(ConfigError::ValidationFailed(
                    format!("Invalid DRM provider: {}, valid options are: {:?}", 
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
                format!("Invalid currency code: {}, must be 3 uppercase letters", 
                        config.default_currency)
            ));
        }
        
        // 验证手续费率
        if config.platform_fee_rate < 0.0 || config.platform_fee_rate > 100.0 {
            return Err(ConfigError::ValidationFailed(
                format!("Platform fee rate must be between 0 and 100: {}", 
                        config.platform_fee_rate)
            ));
        }
        
        // 验证提现金额
        if config.min_withdrawal_amount > config.max_withdrawal_amount {
            return Err(ConfigError::ValidationFailed(
                format!("min_withdrawal_amount ({}) must be <= max_withdrawal_amount ({})", 
                        config.min_withdrawal_amount, config.max_withdrawal_amount)
            ));
        }
        
        // 验证支付渠道
        for (channel_name, channel_config) in &config.channels {
            if channel_config.enabled {
                if channel_config.fee_rate < 0.0 || channel_config.fee_rate > 100.0 {
                    return Err(ConfigError::ValidationFailed(
                        format!("Channel {} fee rate must be between 0 and 100: {}", 
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
        if std::env::var("RUN_MODE").unwrap_or_default() == "development" {
            // 开发环境使用弱密码警告
            if config.jwt.secret == "your-super-secret-jwt-key-change-in-production" {
                warn!("Using default JWT secret in development mode");
            }
            
            if config.encryption.key == base64::encode(vec![0u8; 32]) {
                warn!("Using default encryption key in development mode");
            }
        }
        
        // 生产环境检查
        if std::env::var("RUN_MODE").unwrap_or_default() == "production" {
            // 生产环境必须使用HTTPS
            if !config.server.enable_https {
                return Err(ConfigError::ValidationFailed(
                    "HTTPS must be enabled in production environment".to_string()
                ));
            }
            
            // 生产环境必须使用安全的JWT密钥
            if config.jwt.secret.len() < 64 {
                return Err(ConfigError::ValidationFailed(
                    "JWT secret must be at least 64 characters in production".to_string()
                ));
            }
            
            // 生产环境必须配置数据库SSL
            if !config.database.enable_ssl {
                warn!("Database SSL is not enabled in production environment");
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
                warn!("Multi-storage enabled but less than 2 storage providers are enabled");
            }
        }
        
        // 检查缓存配置一致性
        if config.cache.enabled {
            if !config.cache.enable_memory && !config.cache.enable_redis {
                warn!("Cache enabled but no cache backend is enabled");
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
                    "Queue enabled but no queue provider is enabled".to_string()
                ));
            }
            
            if enabled_count > 1 {
                warn!("Multiple queue providers are enabled, only one will be used");
            }
        }
        
        // 检查监控配置一致性
        if config.telemetry.enabled {
            if config.telemetry.endpoint.is_empty() {
                warn!("Telemetry enabled but endpoint is empty");
            }
        }
        
        Ok(())
    }
    
    /// 验证配置文件的语法
    pub fn validate_syntax(content: &str) -> ConfigResult<()> {
        toml::from_str::<AppConfig>(content)
            .map_err(|e| ConfigError::ValidationFailed(format!("Invalid config syntax: {}", e)))?;
        
        Ok(())
    }
    
    /// 验证配置文件路径
    pub fn validate_file_path(path: &str) -> ConfigResult<()> {
        let path = std::path::Path::new(path);
        
        if !path.exists() {
            return Err(ConfigError::ValidationFailed(
                format!("Config file does not exist: {:?}", path)
            ));
        }
        
        if !path.is_file() {
            return Err(ConfigError::ValidationFailed(
                format!("Path is not a file: {:?}", path)
            ));
        }
        
        // 检查文件扩展名
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");
        
        if !["toml", "json", "yaml", "yml"].contains(&extension) {
            warn!("Config file has unusual extension: .{}", extension);
        }
        
        Ok(())
    }
    
    /// 生成配置验证报告
    pub fn generate_validation_report(config: &AppConfig) -> ValidationReport {
        let mut report = ValidationReport::new();
        
        // 检查关键配置项
        if config.jwt.secret.len() < 32 {
            report.add_warning("JWT secret is too short".to_string());
        }
        
        if config.encryption.key == base64::encode(vec![0u8; 32]) {
            report.add_warning("Using default encryption key".to_string());
        }
        
        if !config.server.enable_https {
            report.add_warning("HTTPS is not enabled".to_string());
        }
        
        // 检查推荐配置
        if config.server.worker_threads < 2 {
            report.add_warning("Worker threads is less than 2".to_string());
        }
        
        if config.database.max_connections < 10 {
            report.add_warning("Database max connections is less than 10".to_string());
        }
        
        if config.redis.pool_size < 5 {
            report.add_warning("Redis pool size is less than 5".to_string());
        }
        
        // 检查特性配置
        if config.features.enable_registration && !config.features.enable_email_verification {
            report.add_warning("Registration enabled but email verification disabled".to_string());
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
        format!("Validation {}: {} warnings, {} errors",
                if self.is_passed() { "passed" } else { "failed" },
                self.warnings.len(),
                self.errors.len())
    }
    
    /// 生成详细报告
    pub fn generate_detailed_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str(&format!("Validation Report\n"));
        report.push_str(&format!("================\n\n"));
        report.push_str(&format!("Status: {}\n\n", 
            if self.is_passed() { "PASSED" } else { "FAILED" }));
        
        if !self.errors.is_empty() {
            report.push_str("Errors:\n");
            for error in &self.errors {
                report.push_str(&format!("  - {}\n", error));
            }
            report.push_str("\n");
        }
        
        if !self.warnings.is_empty() {
            report.push_str("Warnings:\n");
            for warning in &self.warnings {
                report.push_str(&format!("  - {}\n", warning));
            }
            report.push_str("\n");
        }
        
        report.push_str(&format!("Total: {} errors, {} warnings\n", 
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
            let report = validator.generate_validation_report(config);
            if !report.is_passed() {
                warn!("Config validation completed with warnings: {}", report.summary());
            } else {
                info!("Config validation passed: {}", report.summary());
            }
            Ok(report)
        }
        Err(e) => {
            error!("Config validation failed: {}", e);
            let mut report = ValidationReport::new();
            report.add_error(e.to_string());
            Err(ConfigError::ValidationFailed(format!("Config validation failed: {}", e)))
        }
    }
}

/// 便捷函数：验证配置文件
pub fn validate_config_file(path: &str) -> ConfigResult<ValidationReport> {
    // 验证文件路径
    ConfigValidator::validate_file_path(path)?;
    
    // 读取文件内容
    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::IoError(format!("Failed to read config file: {}", e)))?;
    
    // 验证语法
    ConfigValidator::validate_syntax(&content)?;
    
    // 加载配置
    let config: AppConfig = toml::from_str(&content)
        .map_err(|e| ConfigError::DeserializationFailed(format!("Failed to deserialize config: {}", e)))?;
    
    // 验证配置
    validate_config(&config)
}