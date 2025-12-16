use std::collections::HashMap;
use serde_json::Value;
use crate::error::ConfigResult;

/// 配置合并器
pub struct ConfigMerger;

impl ConfigMerger {
    /// 深度合并两个JSON值
    pub fn deep_merge(base: &mut Value, overlay: &Value, replace_arrays: bool) {
        match overlay {
            Value::Object(overlay_map) => {
                if let Some(base_map) = base.as_object_mut() {
                    // 两个都是对象，递归合并
                    for (key, overlay_value) in overlay_map {
                        if let Some(base_value) = base_map.get_mut(key) {
                            // 递归合并
                            Self::deep_merge(base_value, overlay_value, replace_arrays);
                        } else {
                            // 添加新字段
                            base_map.insert(key.clone(), overlay_value.clone());
                        }
                    }
                } else {
                    // base 不是对象，直接覆盖
                    *base = overlay.clone();
                }
            }
            Value::Array(overlay_arr) => {
                if let Some(base_arr) = base.as_array_mut() {
                    // 两个都是数组
                    if replace_arrays {
                        // 替换整个数组
                        *base = Value::Array(overlay_arr.clone());
                    } else {
                        // 合并数组（去重）
                        for item in overlay_arr {
                            if !base_arr.contains(item) {
                                base_arr.push(item.clone());
                            }
                        }
                    }
                } else {
                    // base 不是数组，直接覆盖
                    *base = overlay.clone();
                }
            }
            _ => {
                // 其他类型直接覆盖
                *base = overlay.clone();
            }
        }
    }
    
    /// 合并多个配置
    pub fn merge_configs(configs: Vec<&Value>, replace_arrays: bool) -> Value {
        if configs.is_empty() {
            return Value::Null;
        }
        
        let mut result = configs[0].clone();
        
        for config in configs.iter().skip(1) {
            Self::deep_merge(&mut result, config, replace_arrays);
        }
        
        result
    }
    
    /// 合并TOML配置
    pub fn merge_toml_configs(base: &str, overlay: &str, replace_arrays: bool) -> ConfigResult<String> {
        let base_value: Value = toml::from_str(base)
            .map_err(|e| crate::error::ConfigError::DeserializationFailed(format!("解析基本 TOML 失败: {}", e)))?;
        
        let overlay_value: Value = toml::from_str(overlay)
            .map_err(|e| crate::error::ConfigError::DeserializationFailed(format!("解析覆载 toml 失败: {}", e)))?;
        
        let mut merged_value = base_value.clone();
        Self::deep_merge(&mut merged_value, &overlay_value, replace_arrays);
        
        let merged_toml = toml::to_string_pretty(&merged_value)
            .map_err(|e| crate::error::ConfigError::SerializationFailed(format!("合并的 toml 序列化失败: {}", e)))?;
        
        Ok(merged_toml)
    }
    
    /// 将配置转换为扁平化的键值对
    pub fn flatten_config(config: &Value, prefix: &str) -> HashMap<String, Value> {
        let mut result = HashMap::new();
        
        match config {
            Value::Object(map) => {
                for (key, value) in map {
                    let new_prefix = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    
                    let flattened = Self::flatten_config(value, &new_prefix);
                    result.extend(flattened);
                }
            }
            Value::Array(arr) => {
                for (index, value) in arr.iter().enumerate() {
                    let new_prefix = format!("{}[{}]", prefix, index);
                    let flattened = Self::flatten_config(value, &new_prefix);
                    result.extend(flattened);
                }
            }
            _ => {
                result.insert(prefix.to_string(), config.clone());
            }
        }
        
        result
    }
    
    /// 从扁平化的键值对重建配置
    pub fn unflatten_config(flat_config: &HashMap<String, Value>) -> Value {
        let mut result = Value::Object(serde_json::Map::new());
        
        for (key, value) in flat_config {
            let parts: Vec<&str> = key.split('.').collect();
            Self::insert_value(&mut result, parts, value.clone());
        }
        
        result
    }
    
    /// 插入值到配置树中
    fn insert_value(current: &mut Value, mut path: Vec<&str>, value: Value) {
        if path.is_empty() {
            *current = value;
            return;
        }
        
        let key = path.remove(0);
        
        // 处理数组索引
        if key.contains('[') && key.ends_with(']') {
            let (array_key, index_str) = key.split_once('[').unwrap();
            let index: usize = index_str.trim_end_matches(']').parse().unwrap_or(0);
            
            if let Value::Object(map) = current {
                let array = map
                    .entry(array_key.to_string())
                    .or_insert_with(|| Value::Array(Vec::new()));
                
                if let Value::Array(arr) = array {
                    // 确保数组足够大
                    while arr.len() <= index {
                        arr.push(Value::Null);
                    }
                    
                    Self::insert_value(&mut arr[index], path, value);
                }
            }
        } else {
            match current {
                Value::Object(map) => {
                    let entry = map
                        .entry(key.to_string())
                        .or_insert_with(|| Value::Object(serde_json::Map::new()));
                    
                    Self::insert_value(entry, path, value);
                }
                _ => {
                    // 如果当前不是对象，则替换为对象
                    let mut map = serde_json::Map::new();
                    map.insert(key.to_string(), Value::Object(serde_json::Map::new()));
                    *current = Value::Object(map);
                    
                    if let Value::Object(new_map) = current {
                        if let Some(entry) = new_map.get_mut(key) {
                            Self::insert_value(entry, path, value);
                        }
                    }
                }
            }
        }
    }
    
    /// 计算配置差异
    pub fn diff_configs(old_config: &Value, new_config: &Value) -> ConfigDiff {
        let old_flat = Self::flatten_config(old_config, "");
        let new_flat = Self::flatten_config(new_config, "");
        
        let mut added = HashMap::new();
        let mut modified = HashMap::new();
        let mut removed = HashMap::new();
        
        // 找出新增和修改的项
        for (key, new_value) in &new_flat {
            match old_flat.get(key) {
                Some(old_value) => {
                    if old_value != new_value {
                        modified.insert(key.clone(), (old_value.clone(), new_value.clone()));
                    }
                }
                None => {
                    added.insert(key.clone(), new_value.clone());
                }
            }
        }
        
        // 找出删除的项
        for (key, old_value) in &old_flat {
            if !new_flat.contains_key(key) {
                removed.insert(key.clone(), old_value.clone());
            }
        }
        
        ConfigDiff {
            added,
            modified,
            removed,
        }
    }
    
    /// 应用配置差异
    pub fn apply_diff(config: &mut Value, diff: &ConfigDiff) {
        let mut flat_config = Self::flatten_config(config, "");
        
        // 应用新增和修改
        for (key, value) in &diff.added {
            flat_config.insert(key.clone(), value.clone());
        }
        
        for (key, (_, new_value)) in &diff.modified {
            flat_config.insert(key.clone(), new_value.clone());
        }
        
        // 应用删除
        for key in diff.removed.keys() {
            flat_config.remove(key);
        }
        
        *config = Self::unflatten_config(&flat_config);
    }
}

/// 配置差异
#[derive(Debug, Clone)]
pub struct ConfigDiff {
    pub added: HashMap<String, Value>,
    pub modified: HashMap<String, (Value, Value)>,
    pub removed: HashMap<String, Value>,
}

impl ConfigDiff {
    /// 检查是否有差异
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.modified.is_empty() || !self.removed.is_empty()
    }
    
    /// 获取摘要
    pub fn summary(&self) -> String {
        format!(
            "已添加：{}，已修改：{}，已删除: {}",
            self.added.len(),
            self.modified.len(),
            self.removed.len()
        )
    }
}