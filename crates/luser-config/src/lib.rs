//! Luser配置管理模块
//! 
//! 这个模块负责加载、验证和管理应用程序的所有配置。
//! 支持多环境配置、加密配置项、热重载和配置缓存。

#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

mod config;
mod database;
mod loader;
mod manager;
mod merger;
mod validator;
mod encryption;
mod error;
mod constants;
mod tests;

pub use config::*;
pub use loader::*;
pub use manager::*;
pub use merger::*;
pub use validator::*;
pub use encryption::*;
pub use database::*;
pub use error::*;
pub use constants::*;

/// 重新导出常用的配置类型和函数
pub mod prelude {
    pub use crate::{
        AppConfig, ConfigLoader, ConfigManager, ConfigValidator,
        ConfigError, ConfigResult, ConfigSourceType, load_config, get_config,init_global_encryptor, get_global_encryptor,
        DEFAULT_CONFIG_PATH, ENV_PREFIX,
    };
}



/// 模块版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");