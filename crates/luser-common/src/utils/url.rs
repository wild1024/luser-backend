use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

/// 构建查询字符串
pub fn build_query_string(params: &[(&str, &str)]) -> String {
    let encoded_params: Vec<String> = params
        .iter()
        .map(|(key, value)| {
            let encoded_key = utf8_percent_encode(key, NON_ALPHANUMERIC).to_string();
            let encoded_value = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
            format!("{}={}", encoded_key, encoded_value)
        })
        .collect();

    encoded_params.join("&")
}

/// 解析查询字符串
pub fn parse_query_string(query: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();

    for pair in query.split('&') {
        let parts: Vec<&str> = pair.split('=').collect();
        if parts.len() == 2 {
            params.insert(
                percent_encoding::percent_decode_str(parts[0])
                    .decode_utf8_lossy()
                    .to_string(),
                percent_encoding::percent_decode_str(parts[1])
                    .decode_utf8_lossy()
                    .to_string(),
            );
        }
    }

    params
}

/// 添加查询参数到URL
pub fn add_query_params(base_url: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return base_url.to_string();
    }

    let query_string = build_query_string(params);

    if base_url.contains('?') {
        format!("{}&{}", base_url, query_string)
    } else {
        format!("{}?{}", base_url, query_string)
    }
}
