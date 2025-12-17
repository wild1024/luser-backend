//! Luser平台公共库
//!
//! 提供跨crate共享的类型定义、工具函数和错误处理

#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

mod constants;
mod error;
mod pagination;
mod types;
mod utils;
mod validation;

pub mod cache;
pub mod dto;
pub mod enums;
pub mod middleware;
pub mod traits;

pub use constants::*;
pub use error::*;
pub use pagination::*;
pub use types::*;
pub use utils::*;
pub use validation::*;

/// 重新导出常用的公共类型
pub mod prelude {
    pub use crate::{
        AppError, DEFAULT_PAGE_SIZE, FilterParams, MAX_PAGE_SIZE, PageParams, PaginatedResult,
        PaginationBuilder, Result, SearchParams, SortParams,
        enums::{CloudVendor, PaymentStatus, Role, SubscriptionPlan, UserStatus, VideoStatus},
        validate_email, validate_password, validate_phone,
    };
}
