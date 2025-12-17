use chrono::{DateTime, Duration, TimeZone, Utc};
use std::time::{SystemTime, UNIX_EPOCH};
/// 获取当前时间戳（毫秒）
pub fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// 获取当前时间戳（秒）
pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 格式化时间
pub fn format_time(dt: &DateTime<Utc>, format: &str) -> String {
    dt.format(format).to_string()
}

/// 解析时间字符串
pub fn parse_time(time_str: &str, format: &str) -> Result<DateTime<Utc>, crate::AppError> {
    chrono::NaiveDateTime::parse_from_str(time_str, format)
        .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
        .map_err(|e| crate::AppError::internal(format!("时间解析失败: {}", e)))
}

/// 检查时间是否在范围内
pub fn is_time_in_range(
    time: &DateTime<Utc>,
    start: Option<&DateTime<Utc>>,
    end: Option<&DateTime<Utc>>,
) -> bool {
    if let Some(start_time) = start {
        if time < start_time {
            return false;
        }
    }

    if let Some(end_time) = end {
        if time > end_time {
            return false;
        }
    }

    true
}
/// 计算相对时间
pub fn relative_time(dt: DateTime<Utc>) -> String {
    let now = Utc::now();
    let diff = now - dt;

    if diff.num_seconds() < 60 {
        "刚刚".to_string()
    } else if diff.num_minutes() < 60 {
        format!("{}分钟前", diff.num_minutes())
    } else if diff.num_hours() < 24 {
        format!("{}小时前", diff.num_hours())
    } else if diff.num_days() < 30 {
        format!("{}天前", diff.num_days())
    } else if diff.num_weeks() < 52 {
        format!("{}周前", diff.num_weeks())
    } else {
        format!("{}年前", diff.num_days() / 365)
    }
}

/// 获取一天的开始时间
pub fn start_of_day(dt: DateTime<Utc>) -> DateTime<Utc> {
    dt.date().and_hms(0, 0, 0)
}

/// 获取一天的结束时间
pub fn end_of_day(dt: DateTime<Utc>) -> DateTime<Utc> {
    dt.date().and_hms(23, 59, 59)
}

/// 添加天数
pub fn add_days(dt: DateTime<Utc>, days: i64) -> DateTime<Utc> {
    dt + Duration::days(days)
}

/// 系统时间转UTC时间
pub fn system_time_to_datetime(sys_time: SystemTime) -> DateTime<Utc> {
    let duration = sys_time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    Utc.timestamp_opt(duration.as_secs() as i64, duration.subsec_nanos())
        .unwrap()
}
