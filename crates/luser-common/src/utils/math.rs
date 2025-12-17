use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};

/// 计算百分比
pub fn calculate_percentage(part: f64, total: f64) -> f64 {
    if total == 0.0 {
        return 0.0;
    }

    (part / total) * 100.0
}

/// 计算增长率
pub fn calculate_growth_rate(current: f64, previous: f64) -> f64 {
    if previous == 0.0 {
        return 0.0;
    }

    ((current - previous) / previous) * 100.0
}

/// 精度计算（金融计算用）
pub fn calculate_with_precision(value: f64, precision: usize) -> f64 {
    let bd = BigDecimal::from_f64(value).unwrap_or_default();
    let rounded = bd.round(precision as i64);
    rounded.to_f64().unwrap_or(value)
}

/// 分转元（人民币）
pub fn fen_to_yuan(fen: i64) -> f64 {
    fen as f64 / 100.0
}

/// 元转分（人民币）
pub fn yuan_to_fen(yuan: f64) -> i64 {
    (yuan * 100.0).round() as i64
}

/// 计算手续费
pub fn calculate_fee(amount: f64, fee_rate: f64) -> f64 {
    let fee = amount * fee_rate / 100.0;
    calculate_with_precision(fee, 2)
}
