use rand::Rng;
use uuid::Uuid;
use super::*;
/// 生成随机字符串
pub fn random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789";

    let mut rng = rand::rng();
    let string: String = (0..length)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    string
}

/// 掩码字符串（用于日志）
pub fn mask_string(s: &str, start: usize, end: usize, mask_char: char) -> String {
    if s.len() <= start + end {
        return s.to_string();
    }

    let prefix = &s[0..start];
    let suffix = &s[s.len() - end..];
    let mask_len = s.len() - start - end;

    format!(
        "{}{}{}",
        prefix,
        mask_char.to_string().repeat(mask_len),
        suffix
    )
}

/// 掩码邮箱
pub fn mask_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return email.to_string();
    }

    let username = parts[0];
    let domain = parts[1];

    if username.len() <= 2 {
        return format!("{}@{}", mask_string(username, 0, 0, '*'), domain);
    }

    let masked_username = mask_string(username, 1, 1, '*');
    format!("{}@{}", masked_username, domain)
}

/// 掩码手机号
pub fn mask_phone(phone: &str) -> String {
    if phone.len() <= 7 {
        return phone.to_string();
    }

    mask_string(phone, 3, 4, '*')
}

/// 隐藏敏感数据（用于日志）
pub fn mask_sensitive_data(input: &str) -> String {
    let patterns = vec![
        (r"([^:]+):([^@]+)@", r"$1:****@"),
        (r"password=([^&]+)", r"password=****"),
    ];

    let mut result = input.to_string();
    for (pattern, replacement) in patterns {
        let re = regex::Regex::new(pattern).unwrap();
        result = re.replace_all(&result, replacement).to_string();
    }

    result
}
/// 生成会话ID
pub fn generate_session_id() -> String {
    format!("session-{}", string::random_string(32))
}
/// 生成订单号
pub fn generate_order_no(prefix: &str) -> String {
    let timestamp = time::current_timestamp_ms();
    let random_part = string::random_string(6);
    format!("{}{}{}", prefix, timestamp, random_part)
}

/// 生成支付交易号
pub fn generate_transaction_no() -> String {
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let random_part: u32 = rand::rng().random_range(100000..999999);
    format!("T{}{}", timestamp, random_part)
}

/// 生成视频ID（云服务商兼容）
pub fn generate_video_id() -> String {
    format!("video-{}", Uuid::new_v4())
}

/// 生成上传ID
pub fn generate_upload_id() -> String {
    format!("upload-{}", Uuid::new_v4())
}

/// 格式化金额（分转元）
pub fn format_amount(fen: i64) -> String {
    let yuan = math::fen_to_yuan(fen);
    format!("¥{:.2}", yuan)
}
