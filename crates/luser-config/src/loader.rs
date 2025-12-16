use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    AppConfig, ConfigError, ConfigResult, ConfigSourceType, DEFAULT_CONFIG_FILE,
    DEFAULT_CONFIG_PATH, DEFAULT_RUN_MODE, DatabaseConfigLoader, ENV_PREFIX, RUN_MODE_ENV,
};
use chrono::Utc;
use config::{Config, ConfigBuilder, Environment, File, FileFormat};
use parking_lot::RwLock;
use sqlx::{Pool, Postgres};
use tracing::debug;
use tracing::{info, instrument, warn};
/// 配置合并优先级（从低到高）
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigPriority {
    /// 最低优先级：默认值
    Defaults = 1,
    /// 较低优先级：默认配置文件
    DefaultFile = 2,
    /// 中等优先级：环境特定配置文件
    EnvironmentFile = 3,
    /// 较高优先级：环境变量
    EnvironmentVariables = 4,
    /// 最高优先级：数据库配置
    Database = 5,
    /// 运行时优先级：内存覆盖
    Runtime = 6,
}

/// 配置合并策略
#[derive(Debug, Clone)]
pub struct MergeStrategy {
    /// 是否启用深度合并
    pub deep_merge: bool,
    /// 是否覆盖数组
    pub replace_arrays: bool,
    /// 是否保留未定义的字段
    pub keep_undefined: bool,
    /// 是否启用调试日志
    pub debug: bool,
}

impl Default for MergeStrategy {
    fn default() -> Self {
        Self {
            deep_merge: true,
            replace_arrays: false,
            keep_undefined: false,
            debug: false,
        }
    }
}

/// 配置加载器
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    sources: Vec<ConfigSource>,
    environment: String,
    config_dir: PathBuf,
    /// 合并策略
    merge_strategy: MergeStrategy,
    /// 数据库连接池（用于动态配置）
     db_pool: Option<Arc<Pool<Postgres>>>,
    /// 配置缓存（数据库配置）
    db_config_cache: Arc<RwLock<Option<AppConfig>>>,
    /// 最后更新时间
    last_update_time: Arc<RwLock<chrono::DateTime<Utc>>>,
}
/// 配置源
#[derive(Debug, Clone)]
pub struct ConfigSource {
    /// 源类型
    pub source_type: ConfigSourceType,
    /// 配置数据
    pub data: config::Config,
    /// 优先级
    pub priority: ConfigPriority,
    /// 时间戳
    pub timestamp: chrono::DateTime<Utc>,
    /// 描述
    pub description: String,
}

impl ConfigLoader {
    /// 创建新的配置加载器
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            environment: std::env::var(RUN_MODE_ENV)
                .unwrap_or_else(|_| DEFAULT_RUN_MODE.to_string()),
            config_dir: PathBuf::from(DEFAULT_CONFIG_PATH),
            merge_strategy: MergeStrategy::default(),
            db_pool: None,
            db_config_cache: Arc::new(RwLock::new(None)),
            last_update_time: Arc::new(RwLock::new(Utc::now())),
        }
    }

    /// 设置环境
    pub fn set_environment(&mut self, env: &str) -> &mut Self {
        self.environment = env.to_string();
        self
    }
    /// 获取环境
    pub fn get_env(&mut self) -> String {
        self.environment.clone() 
    }
    /// 设置配置目录
    pub fn set_config_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.config_dir = dir.as_ref().to_path_buf();
        self
    }
    /// 设置合并策略
    pub fn set_merge_strategy(&mut self, strategy: MergeStrategy) -> &mut Self {
        self.merge_strategy = strategy;
        self
    }
    /// 设置数据库连接池（用于动态配置）
    pub fn set_database_pool(&mut self, pool: Pool<Postgres>) -> &mut Self {
        self.db_pool = Some(Arc::new(pool));
        self
    }
    pub fn get_db_pool(&self) -> Option<Arc<Pool<Postgres>>>{
         self.db_pool.clone()
    }
    /// 添加配置文件源
    fn add_source_file(
        &mut self,
        path: &Path,
        priority: ConfigPriority,
        description: &str,
    ) -> ConfigResult<()> {
        let config = Config::builder()
            .add_source(File::from(path))
            .build()
            .map_err(|e| {
                ConfigError::LoadFailed(format!(
                    "无法从 {:?}中构建文件配置: {}",
                    path, e
                ))
            })?;

        self.sources.push(ConfigSource {
            source_type: ConfigSourceType::File,
            data: config,
            priority,
            timestamp: Utc::now(),
            description: description.to_string(),
        });

        Ok(())
    }
    /// 添加默认值源
    pub fn add_defaults_source(&mut self) -> ConfigResult<&mut Self> {
        // 创建默认配置
        let default_config = AppConfig::default();

        // 将默认配置转换为config::Config
        let default_toml = toml::to_string_pretty(&default_config).map_err(|e| {
            ConfigError::SerializationFailed(format!("无法序列化默认配置: {}", e))
        })?;

        let config = Config::builder()
            .add_source(File::from_str(&default_toml, FileFormat::Toml))
            .build()
            .map_err(|e| {
                ConfigError::LoadFailed(format!("构建默认配置失败: {}", e))
            })?;

        self.sources.push(ConfigSource {
            source_type: ConfigSourceType::Default,
            data: config,
            priority: ConfigPriority::Defaults,
            timestamp: Utc::now(),
            description: "默认配置值".to_string(),
        });

        Ok(self)
    }
    /// 添加默认配置文件源
    pub fn add_default_file_source(&mut self) -> ConfigResult<&mut Self> {
        let default_config_path = self.config_dir.join(DEFAULT_CONFIG_FILE);

        if default_config_path.exists() {
            self.add_source_file(
                &default_config_path,
                ConfigPriority::DefaultFile,
                "默认配置文件",
            )?;
        } else {
            warn!("未找到默认配置文件: {:?}", default_config_path);
        }

        Ok(self)
    }
    /// 添加环境特定配置文件源
    pub fn add_environment_file_source(&mut self) -> ConfigResult<&mut Self> {
        let env_config_path = self.config_dir.join(format!("{}.toml", self.environment));

        if env_config_path.exists() {
            self.add_source_file(
                &env_config_path,
                ConfigPriority::EnvironmentFile,
                &format!("{} 环境配置文件", self.environment),
            )?;
        } else {
            debug!("未找到: {:?} 环境配置文件", env_config_path);
        }

        Ok(self)
    }
    /// 添加环境变量源
    pub fn add_environment_variables_source(&mut self) -> ConfigResult<&mut Self> {
        let config = Config::builder()
            .add_source(
                Environment::with_prefix(ENV_PREFIX)
                    .separator("_")
                    .list_separator(",")
                    .try_parsing(true)
                    .with_list_parse_key("allowed_origins")
                    .with_list_parse_key("allowed_methods")
                    .with_list_parse_key("allowed_formats"),
            )
            .build()
            .map_err(|e| {
                ConfigError::LoadFailed(format!("构建环境配置失败: {}", e))
            })?;

        self.sources.push(ConfigSource {
            source_type: ConfigSourceType::Environment,
            data: config,
            priority: ConfigPriority::EnvironmentVariables,
            timestamp: Utc::now(),
            description: "环境变量".to_string(),
        });

        Ok(self)
    }
    /// 添加数据库配置源
    pub async fn add_database_source(&mut self) -> ConfigResult<&mut Self> {
        if let Some(pool) = &self.db_pool {
            // 从数据库加载配置
            match DatabaseConfigLoader::load_config_from_db(pool, &self.environment).await {
                Ok(Some(config_map)) => {
                    // 将配置转换为TOML格式
                    let toml_string = toml::to_string(&config_map).map_err(|e| {
                        ConfigError::SerializationFailed(format!(
                            "无法序列化数据库配置: {}",
                            e
                        ))
                    })?;

                    // 构建config::Config
                    let config = Config::builder()
                        .add_source(File::from_str(&toml_string, FileFormat::Toml))
                        .build()
                        .map_err(|e| {
                            ConfigError::LoadFailed(format!(
                                "创建数据库配置失败: {}",
                                e
                            ))
                        })?;

                    self.sources.push(ConfigSource {
                        source_type: ConfigSourceType::Database,
                        data: config,
                        priority: ConfigPriority::Database,
                        timestamp: Utc::now(),
                        description: "数据库配置".to_string(),
                    });

                    // 缓存合并后的配置
                    if let Ok(merged) = self.merge_sources() {
                        if let Ok(app_config) = merged.try_deserialize::<AppConfig>() {
                            *self.db_config_cache.write() = Some(app_config);
                        }
                    }
                }
                Ok(None) => {
                    debug!("未找到数据库配置");
                }
                Err(e) => {
                    warn!("加载数据库配置失败: {}", e);
                }
            }
        } else {
            debug!("数据库池未设置，跳过数据库配置");
        }

        Ok(self)
    }
    /// 同步版本：从数据库加载配置（用于同步上下文）
    fn add_database_source_sync(&mut self) -> ConfigResult<&mut Self> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| ConfigError::LoadFailed("不在 Tokio 运行时中".to_string()))?;

        runtime.block_on(async { self.add_database_source().await })
    }
    /// 添加自定义配置源
    pub fn add_custom_source<F>(
        &mut self,
        priority: ConfigPriority,
        description: &str,
        builder: F,
    ) -> ConfigResult<&mut Self>
    where
        F: FnOnce(
            ConfigBuilder<config::builder::DefaultState>,
        ) -> ConfigResult<ConfigBuilder<config::builder::DefaultState>>,
    {
        let base_builder = Config::builder();
        let config_builder = builder(base_builder)?;

        let config = config_builder.build().map_err(|e| {
            ConfigError::LoadFailed(format!("构建自定义配置失败: {}", e))
        })?;

        self.sources.push(ConfigSource {
            source_type: ConfigSourceType::Custom,
            data: config,
            priority,
            timestamp: Utc::now(),
            description: description.to_string(),
        });

        Ok(self)
    }
    /// 添加默认配置源
    fn add_default_sources(&mut self) -> ConfigResult<()> {
        // 清空现有源
        self.sources.clear();

        // 按照优先级从低到高添加源

        self.add_defaults_source()?;
        self.add_default_file_source()?;
        self.add_environment_file_source()?;
        self.add_environment_variables_source()?;

        // 同步方式添加数据库配置
        self.add_database_source_sync()?;

        Ok(())
    }

    /// 加载配置
    #[instrument(skip(self), name = "config.load")]
    pub fn load(&mut self) -> ConfigResult<AppConfig> {
        info!(
            "正在加载环境配置: {}",
            self.environment
        );

        // 1. 按顺序添加所有配置源
        self.add_default_sources()?;

        // 2. 按照优先级对源进行排序
        self.sources.sort_by(|a, b| a.priority.cmp(&b.priority));

        // 3. 记录所有源
        for source in &self.sources {
            debug!(
                "配置来源: {} (优先级: {:?})",
                source.description, source.priority
            );
        }
        // 4. 合并所有配置源
        let merged_config = self.merge_sources()?;

        // 5. 反序列化为AppConfig
        let app_config: AppConfig = merged_config.try_deserialize().map_err(|e| {
            ConfigError::DeserializationFailed(format!(
                "无法反序列化合并后的配置: {}",
                e
            ))
        })?;

        // 6. 记录合并后的配置摘要
        self.log_config_summary(&app_config);

        info!(
            "配置已成功加载，共有 {} 个来源",
            self.sources.len()
        );

        Ok(app_config)
    }
    /// 异步版本：加载配置
    #[instrument(skip(self), name = "config.load_async")]
    pub async fn load_async(&mut self) -> ConfigResult<AppConfig> {
        info!(
            "正在加载环境配置： {}",
            self.environment
        );

        // 按顺序添加所有配置源
        self.sources.clear();
        self.add_defaults_source()?;
        self.add_default_file_source()?;
        self.add_environment_file_source()?;
        self.add_environment_variables_source()?;
        self.add_database_source().await?;

        // 按照优先级对源进行排序
        self.sources.sort_by(|a, b| a.priority.cmp(&b.priority));

        // 合并所有配置源
        let merged_config = self.merge_sources()?;

        // 反序列化为AppConfig
        let app_config: AppConfig = merged_config.try_deserialize().map_err(|e| {
            ConfigError::DeserializationFailed(format!(
                "反序列化合并配置失败： {}",
                e
            ))
        })?;

        self.log_config_summary(&app_config);
        info!(
            "配置已成功加载，共 {} 个来源",
            self.sources.len()
        );

        Ok(app_config)
    }
    /// 合并所有配置源
    fn merge_sources(&self) -> ConfigResult<Config> {
        let mut current_config = Config::builder();

        // 按照优先级顺序合并
        for source in &self.sources {
            if self.merge_strategy.debug {
                debug!(
                    "应用配置源：{}（优先级：{:?}）",
                    source.description, source.priority
                );
            }

            current_config = current_config.add_source(source.data.clone());
        }

        // 构建最终配置
        let config = current_config.build().map_err(|e| {
            ConfigError::LoadFailed(format!("构建合并配置失败: {}", e))
        })?;

        Ok(config)
    }

    /// 记录配置摘要
    fn log_config_summary(&self, config: &AppConfig) {
        debug!("配置摘要:");
        debug!("  Server: {}:{}", config.server.host, config.server.port);
        debug!("  Database: {}", config.database.url);
        debug!("  Redis: {}", config.redis.url);
        debug!("  Environment: {}", self.environment);
        debug!("  Sources applied: {}", self.sources.len());

        // 记录每个源的优先级
        for source in &self.sources {
            debug!(
                "    - {} (priority: {:?})",
                source.description, source.priority
            );
        }
    }
    /// 重新加载数据库配置
    pub fn reload_database_config(&mut self) -> ConfigResult<()> {
        if let Some(_) = &self.db_pool {
            let runtime = tokio::runtime::Handle::try_current()
                .map_err(|_| ConfigError::LoadFailed("不在 Tokio 运行时中".to_string()))?;

            runtime.block_on(async { self.reload_database_config_async().await })?;
        }

        Ok(())
    }
    /// 重新加载数据库配置
    pub async fn reload_database_config_async(&mut self) -> ConfigResult<()> {
        if self.db_pool.is_some() {
            // 清除现有的数据库配置源
            self.sources
                .retain(|s| s.source_type != ConfigSourceType::Database);

            // 重新加载数据库配置
            self.add_database_source().await?;

            // 更新最后更新时间
            *self.last_update_time.write() = Utc::now();

            info!("数据库配置已重新加载");
        }

        Ok(())
    }
    
    /// 检查数据库配置是否需要重新加载
    pub async fn should_reload_from_db(&self, interval_seconds: u64) -> Result<bool, ConfigError> {
        let last_update = *self.last_update_time.read();
        let now = Utc::now();
        let duration = now - last_update;

        if duration.num_seconds() >= interval_seconds as i64 {
            if let Some(pool) = &self.db_pool {
                let has_updates = DatabaseConfigLoader::check_config_updated(
                    pool,
                    &self.environment,
                    last_update,
                )
                .await?;

                return Ok(has_updates);
            }
        }

        Ok(false)
    }
  
    /// 获取配置源信息
    pub fn get_source_info(&self) -> Vec<ConfigSourceInfo> {
        self.sources
            .iter()
            .map(|source| ConfigSourceInfo {
                source_type: source.source_type,
                priority: source.priority,
                timestamp: source.timestamp,
                description: source.description.clone(),
            })
            .collect()
    }
    /// 获取数据库配置缓存
    pub fn get_database_config_cache(&self) -> Option<AppConfig> {
        self.db_config_cache.read().clone()
    }

    /// 清除数据库配置缓存
    pub fn clear_database_config_cache(&self) {
        *self.db_config_cache.write() = None;
    }
    /// 检查配置是否需要重新加载
    pub fn should_reload(&self, interval_seconds: u64) -> bool {
        let last_update = *self.last_update_time.read();
        let now = Utc::now();
        let duration = now - last_update;

        duration.num_seconds() >= interval_seconds as i64
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// 配置源信息
#[derive(Debug, Clone)]
pub struct ConfigSourceInfo {
    pub source_type: ConfigSourceType,
    pub priority: ConfigPriority,
    pub timestamp: chrono::DateTime<Utc>,
    pub description: String,
}
