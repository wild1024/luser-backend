use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref EMAIL_REGEX: Regex =
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    static ref PHONE_REGEX: Regex = Regex::new(r"^1[3-9]\d{9}$").unwrap();
    static ref URL_REGEX: Regex = Regex::new(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$").unwrap();
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_]{3,50}$").unwrap();
    static ref CHINESE_NAME_REGEX: Regex = Regex::new(r"^[\u4e00-\u9fa5]{2,10}$").unwrap();
}

/// 验证邮箱格式
pub fn is_valid_email(email: &str) -> bool {
    EMAIL_REGEX.is_match(email)
}

/// 验证手机号格式（中国）
pub fn is_valid_phone(phone: &str) -> bool {
    PHONE_REGEX.is_match(phone)
}

/// 验证URL格式
pub fn is_valid_url(url: &str) -> bool {
    URL_REGEX.is_match(url)
}

/// 验证用户名格式
pub fn is_valid_username(username: &str) -> bool {
    USERNAME_REGEX.is_match(username)
}

/// 验证中文姓名格式
pub fn is_valid_chinese_name(name: &str) -> bool {
    CHINESE_NAME_REGEX.is_match(name)
}

/// 验证身份证号格式（中国，简化版）
pub fn is_valid_id_card(id_card: &str) -> bool {
    if id_card.len() != 18 && id_card.len() != 15 {
        return false;
    }

    // 这里只做基本格式验证，实际应该做更详细的验证
    let id_regex = Regex::new(
        r"^[1-9]\d{5}(19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$",
    )
    .unwrap();
    id_regex.is_match(id_card)
}

/// 验证密码强度
pub fn validate_password_strength(password: &str) -> bool {
    if password.len() < 8 {
        return false;
    }

    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

    // 至少满足三种条件
    let mut conditions_met = 0;
    if has_upper {
        conditions_met += 1;
    }
    if has_lower {
        conditions_met += 1;
    }
    if has_digit {
        conditions_met += 1;
    }
    if has_special {
        conditions_met += 1;
    }

    conditions_met >= 3
}
