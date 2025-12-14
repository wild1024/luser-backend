//! Luser平台公共库
//! 
//! 提供跨crate共享的类型定义、工具函数和错误处理

#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

mod types;
mod error;
mod utils;
mod constants;
mod validation;
mod pagination;

pub use types::*;
pub use error::*;
pub use utils::*;
pub use constants::*;
pub use validation::*;
pub use pagination::*;

/// 重新导出常用的公共类型
pub mod prelude {
    pub use crate::{
        LuserError, LuserResult, ApiResponse, ApiError, Pagination, PaginatedResponse,
        Role, UserStatus, PaymentStatus, VideoStatus, CloudVendor,
        validate_email, validate_phone, validate_password,
        DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE,
    };
}