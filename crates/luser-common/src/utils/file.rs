use std::{path::Path, time::{SystemTime, UNIX_EPOCH}};
use super::*;
/// 获取文件扩展名
pub fn get_extension(filename: &str) -> Option<String> {
    Path::new(filename)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase())
}

/// 获取文件名（不含扩展名）
pub fn get_filename_without_extension(filename: &str) -> String {
    Path::new(filename)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(filename)
        .to_string()
}

/// 格式化文件大小
pub fn format_file_size(size: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];

    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}
/// 格式化时长
pub fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, minutes, secs)
    } else {
        format!("{:02}:{:02}", minutes, secs)
    }
}
/// 获取当前时间戳（毫秒）
pub fn current_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
/// 检查文件类型是否允许
pub fn is_allowed_file_type(
    filename: &str,
    allowed_types: &[&str],
    allowed_extensions: &[&str],
) -> bool {
    // 检查扩展名
    if let Some(ext) = get_extension(filename) {
        if allowed_extensions
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&ext))
        {
            return true;
        }
    }

    // 检查MIME类型（简化版）
    false
}

/// 生成唯一文件名
pub fn generate_unique_filename(original_filename: &str) -> String {
    let extension = get_extension(original_filename)
        .map(|ext| format!(".{}", ext))
        .unwrap_or_default();

    let timestamp = time::current_timestamp_ms();
    let random_part = string::random_string(8);

    format!("{}_{}{}", timestamp, random_part, extension)
}
