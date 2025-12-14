//! 配置常量定义

/// 默认配置文件路径
pub const DEFAULT_CONFIG_PATH: &str = "./config";

/// 默认配置文件名称
pub const DEFAULT_CONFIG_FILE: &str = "default.toml";

/// 环境特定配置文件前缀
pub const ENV_CONFIG_PREFIX: &str = "";

/// 环境特定配置文件后缀
pub const ENV_CONFIG_SUFFIX: &str = ".toml";

/// 环境变量前缀
pub const ENV_PREFIX: &str = "LUSER";

/// 配置加密密钥环境变量
pub const ENCRYPTION_KEY_ENV: &str = "LUSER_ENCRYPTION_KEY";

/// JWT密钥环境变量
pub const JWT_SECRET_ENV: &str = "LUSER_JWT_SECRET";

/// 数据库URL环境变量
pub const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// Redis URL环境变量
pub const REDIS_URL_ENV: &str = "REDIS_URL";

/// 运行模式环境变量
pub const RUN_MODE_ENV: &str = "RUN_MODE";

/// 支持的运行模式
pub const SUPPORTED_RUN_MODES: [&str; 4] = ["development", "test", "staging", "production"];

/// 默认运行模式
pub const DEFAULT_RUN_MODE: &str = "development";

/// 配置缓存键前缀
pub const CONFIG_CACHE_PREFIX: &str = "config:";

/// 配置缓存过期时间（秒）
pub const CONFIG_CACHE_TTL: u64 = 300; // 5分钟

/// 配置监控轮询间隔（秒）
pub const CONFIG_WATCH_INTERVAL: u64 = 5;

/// 配置重新加载信号
pub const CONFIG_RELOAD_SIGNAL: &str = "SIGHUP";

/// 配置文件编码
pub const CONFIG_FILE_ENCODING: &str = "UTF-8";

/// 支持的配置文件格式
pub const SUPPORTED_CONFIG_FORMATS: [&str; 4] = ["toml", "json", "yaml", "yml"];

/// 默认配置文件格式
pub const DEFAULT_CONFIG_FORMAT: &str = "toml";

/// 配置验证规则文件
pub const CONFIG_VALIDATION_RULES_FILE: &str = "validation-rules.toml";

/// 配置模板文件
pub const CONFIG_TEMPLATE_FILE: &str = "config.template.toml";

/// 配置备份目录
pub const CONFIG_BACKUP_DIR: &str = "./backups/config";

/// 配置备份保留天数
pub const CONFIG_BACKUP_RETENTION_DAYS: u32 = 30;

/// 配置变更历史文件
pub const CONFIG_CHANGE_HISTORY_FILE: &str = "./config/changes.log";

/// 配置审计日志文件
pub const CONFIG_AUDIT_LOG_FILE: &str = "./logs/config-audit.log";

/// 配置版本
pub const CONFIG_VERSION: &str = "1.0.0";



/// 加密密钥长度（字节）
pub const ENCRYPTION_KEY_LENGTH: usize = 32;
pub const ENCRYPTION_NONCE_LENGTH: usize = 12;
pub const ENCRYPTION_TAG_LENGTH: usize = 16;

/// 加密标记前缀和后缀
pub const ENCRYPTION_PREFIX: &str = "ENC[";
pub const ENCRYPTION_SUFFIX: &str = "]";

/// 密钥轮换相关常量
pub const KEY_ROTATION_INTERVAL_DAYS: u32 = 90;
pub const KEY_BACKUP_COUNT: usize = 3;


/// 配置源类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSourceType {
    /// 文件配置源
    File,
    /// 环境变量配置源
    Environment,
    /// 命令行配置源
    CommandLine,
    /// 远程配置源
    Remote,
    /// 数据库配置源
    Database,
    /// 自定义配置源 
    Custom,
    /// 默认配置源
    Default,
}

impl ConfigSourceType {
    /// 获取源类型名称
    pub fn name(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Environment => "environment",
            Self::CommandLine => "command_line",
            Self::Remote => "remote",
            Self::Database => "database",
            Self::Custom => "custom",
            Self::Default => "default",

        }
    }
    
    /// 获取源优先级（数值越小优先级越高）
    pub fn priority(&self) -> u8 {
        match self {
            Self::Remote => 1,
            Self::Database => 2,
            Self::Custom => 3,
            Self::CommandLine => 4,
            Self::Environment => 5,
            Self::File => 6,
            Self::Default => 7,
        }
    }
}


/// 配置变更类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigChangeType {
    /// 配置创建
    Created,
    /// 配置更新
    Updated,
    /// 配置删除
    Deleted,
    /// 配置重载
    Reloaded,
    /// 配置回滚
    Rollback,
}

impl ConfigChangeType {
    /// 获取变更类型名称
    pub fn name(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Deleted => "deleted",
            Self::Reloaded => "reloaded",
            Self::Rollback => "rollback",
        }
    }
}

/// 配置安全级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSecurityLevel {
    /// 公开配置（无需加密）
    Public,
    /// 内部配置（建议加密）
    Internal,
    /// 敏感配置（必须加密）
    Sensitive,
    /// 秘密配置（高度加密）
    Secret,
}

impl ConfigSecurityLevel {
    /// 获取安全级别名称
    pub fn name(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
        }
    }
    
    /// 检查是否需要加密
    pub fn requires_encryption(&self) -> bool {
        match self {
            Self::Public => false,
            Self::Internal => true,
            Self::Sensitive => true,
            Self::Secret => true,
        }
    }
    
    /// 检查是否需要严格加密
    pub fn requires_strict_encryption(&self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }
}


/// 配置常量工具函数
pub struct ConfigConstants;

impl ConfigConstants {
    /// 获取所有支持的运行模式
    pub fn supported_run_modes() -> Vec<&'static str> {
        SUPPORTED_RUN_MODES.to_vec()
    }
    
    /// 检查运行模式是否支持
    pub fn is_run_mode_supported(mode: &str) -> bool {
        SUPPORTED_RUN_MODES.contains(&mode.to_lowercase().as_str())
    }
    
    /// 获取默认配置文件路径
    pub fn default_config_path() -> String {
        format!("{}/{}", DEFAULT_CONFIG_PATH, DEFAULT_CONFIG_FILE)
    }
    
    /// 获取环境特定配置文件路径
    pub fn env_config_path(env: &str) -> String {
        format!("{}/{}{}", DEFAULT_CONFIG_PATH, env, ENV_CONFIG_SUFFIX)
    }
    
    /// 获取配置缓存键
    pub fn config_cache_key(key: &str) -> String {
        format!("{}{}", CONFIG_CACHE_PREFIX, key)
    }
    
    /// 获取配置审计日志文件路径
    pub fn config_audit_log_path() -> String {
        CONFIG_AUDIT_LOG_FILE.to_string()
    }
    
    /// 获取配置备份目录路径
    pub fn config_backup_dir() -> String {
        CONFIG_BACKUP_DIR.to_string()
    }
    
    /// 获取配置变更历史文件路径
    pub fn config_change_history_path() -> String {
        CONFIG_CHANGE_HISTORY_FILE.to_string()
    }
    
    /// 获取配置验证规则文件路径
    pub fn config_validation_rules_path() -> String {
        format!("{}/{}", DEFAULT_CONFIG_PATH, CONFIG_VALIDATION_RULES_FILE)
    }
    
    /// 获取配置模板文件路径
    pub fn config_template_path() -> String {
        format!("{}/{}", DEFAULT_CONFIG_PATH, CONFIG_TEMPLATE_FILE)
    }
}