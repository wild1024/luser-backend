//! Luser配置管理模块
//! 
//! 这个模块负责加载、验证和管理应用程序的所有配置。
//! 支持多环境配置、加密配置项、热重载和配置缓存。

#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

mod config;
mod loader;
mod validator;
mod encryption;
mod watcher;
mod cache;
mod error;
mod constants;
mod utils;
mod tests;

pub use config::*;
pub use loader::*;
pub use validator::*;
pub use encryption::*;
pub use watcher::*;
pub use cache::*;
pub use error::*;
pub use constants::*;
pub use utils::*;

/// 重新导出常用的配置类型和函数
pub mod prelude {
    pub use crate::{
        AppConfig, ConfigLoader, ConfigValidator, ConfigWatcher,
        ConfigError, ConfigResult, load_config, get_config,
        DEFAULT_CONFIG_PATH, ENV_PREFIX,
    };
}

/// 生成构建信息
include!(concat!(env!("OUT_DIR"), "/built.rs"));

/// 模块版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");