use validator:: ValidationError;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    ).unwrap();
    
    static ref PHONE_REGEX: Regex = Regex::new(
        r"^1[3-9]\d{9}$"
    ).unwrap();
    
    static ref USERNAME_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9_]{3,50}$"
    ).unwrap();
}

/// 验证邮箱格式
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if EMAIL_REGEX.is_match(email) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_email"))
    }
}

/// 验证手机号格式（中国）
pub fn validate_phone(phone: &str) -> Result<(), ValidationError> {
    if PHONE_REGEX.is_match(phone) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_phone"))
    }
}

/// 验证用户名格式
pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    if USERNAME_REGEX.is_match(username) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_username"))
    }
}

/// 验证密码强度
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 {
        return Err(ValidationError::new("password_too_short"));
    }
    
    if password.len() > 100 {
        return Err(ValidationError::new("password_too_long"));
    }
    
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
    
    let mut conditions_met = 0;
    if has_upper { conditions_met += 1; }
    if has_lower { conditions_met += 1; }
    if has_digit { conditions_met += 1; }
    if has_special { conditions_met += 1; }
    
    if conditions_met >= 3 {
        Ok(())
    } else {
        Err(ValidationError::new("weak_password"))
    }
}

/// 验证URL格式
pub fn validate_url(url: &str) -> Result<(), ValidationError> {
    if url::Url::parse(url).is_ok() {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_url"))
    }
}

/// 验证文件大小
pub fn validate_file_size(size: u64, max_size: u64) -> Result<(), ValidationError> {
    if size > max_size {
        return Err(ValidationError::new("file_too_large"));
    }
    
    if size == 0 {
        return Err(ValidationError::new("file_empty"));
    }
    
    Ok(())
}

/// 验证金额（分）
pub fn validate_amount(amount: i64, min: i64, max: i64) -> Result<(), ValidationError> {
    if amount < min {
        return Err(ValidationError::new("amount_too_small"));
    }
    
    if amount > max {
        return Err(ValidationError::new("amount_too_large"));
    }
    
    Ok(())
}

/// 验证时间范围
pub fn validate_time_range(
    start_time: Option<chrono::DateTime<chrono::Utc>>,
    end_time: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), ValidationError> {
    if let (Some(start), Some(end)) = (start_time, end_time) {
        if start > end {
            return Err(ValidationError::new("invalid_time_range"));
        }
    }
    
    Ok(())
}

/// 验证页码
pub fn validate_page(page: u32) -> Result<(), ValidationError> {
    if page == 0 {
        return Err(ValidationError::new("invalid_page"));
    }
    
    Ok(())
}

/// 验证每页大小
pub fn validate_page_size(page_size: u32, max_page_size: u32) -> Result<(), ValidationError> {
    if page_size == 0 {
        return Err(ValidationError::new("invalid_page_size"));
    }
    
    if page_size > max_page_size {
        return Err(ValidationError::new("page_size_too_large"));
    }
    
    Ok(())
}

/// 验证排序字段
pub fn validate_sort_field(field: &str, allowed_fields: &[&str]) -> Result<(), ValidationError> {
    if allowed_fields.contains(&field) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_sort_field"))
    }
}

/// 验证排序方向
pub fn validate_sort_order(order: &str) -> Result<(), ValidationError> {
    let order = order.to_lowercase();
    if order == "asc" || order == "desc" {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_sort_order"))
    }
}