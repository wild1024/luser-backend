use serde::{Deserialize, Serialize};
use validator::Validate;

/// 分页参数
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PageParams {
    /// 页码（从1开始）
    #[validate(range(min = 1))]
    pub page: u32,
    
    /// 每页大小
    #[validate(range(min = 1, max = 100))]
    pub page_size: u32,
}

impl Default for PageParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
        }
    }
}

impl PageParams {
    /// 创建分页参数
    pub fn new(page: u32, page_size: u32) -> Self {
        Self { page, page_size }
    }
    
    /// 获取偏移量
    pub fn offset(&self) -> u32 {
        (self.page - 1) * self.page_size
    }
    
    /// 获取限制数量
    pub fn limit(&self) -> u32 {
        self.page_size
    }
    
    /// 转换为SQLx参数
    pub fn to_sqlx_params(&self) -> (i64, i64) {
        (self.offset() as i64, self.limit() as i64)
    }
}

/// 排序参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortParams {
    /// 排序字段
    pub sort_by: Option<String>,
    
    /// 排序方向：asc/desc
    pub sort_order: Option<String>,
}

impl SortParams {
    /// 创建排序参数
    pub fn new(sort_by: Option<String>, sort_order: Option<String>) -> Self {
        Self { sort_by, sort_order }
    }
    
    /// 获取排序SQL片段
    pub fn to_sql(&self, default_sort_by: &str, default_sort_order: &str) -> String {
        let sort_by = self.sort_by.as_deref().unwrap_or(default_sort_by);
        let sort_order = self.sort_order.as_deref().unwrap_or(default_sort_order);
        
        // 防止SQL注入
        let valid_sort_order = if sort_order.to_lowercase() == "desc" {
            "DESC"
        } else {
            "ASC"
        };
        
        format!("{} {}", sort_by, valid_sort_order)
    }
}

/// 搜索参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchParams {
    /// 搜索关键词
    pub keyword: Option<String>,
    
    /// 搜索字段
    pub search_fields: Vec<String>,
}

impl SearchParams {
    /// 创建搜索参数
    pub fn new(keyword: Option<String>, search_fields: Vec<String>) -> Self {
        Self {
            keyword,
            search_fields,
        }
    }
    
    /// 检查是否有搜索关键词
    pub fn has_keyword(&self) -> bool {
        self.keyword.is_some()
    }
    
    /// 获取搜索SQL片段
    pub fn to_sql(&self) -> Option<String> {
        self.keyword.as_ref().map(|keyword| {
            let conditions: Vec<String> = self.search_fields
                .iter()
                .map(|field| format!("{} ILIKE '%{}%'", field, keyword))
                .collect();
            
            format!("({})", conditions.join(" OR "))
        })
    }
}

/// 过滤参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterParams {
    /// 过滤条件
    pub filters: Vec<FilterCondition>,
}

/// 过滤条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterCondition {
    /// 字段名
    pub field: String,
    
    /// 操作符：=, !=, >, <, >=, <=, LIKE, IN, BETWEEN
    pub operator: String,
    
    /// 值
    pub value: serde_json::Value,
    
    /// 第二个值（用于BETWEEN）
    pub second_value: Option<serde_json::Value>,
}

impl FilterParams {
    /// 创建过滤参数
    pub fn new(filters: Vec<FilterCondition>) -> Self {
        Self { filters }
    }
    
    /// 添加过滤条件
    pub fn add_filter(&mut self, field: &str, operator: &str, value: serde_json::Value) {
        self.filters.push(FilterCondition {
            field: field.to_string(),
            operator: operator.to_string(),
            value,
            second_value: None,
        });
    }
    
}

/// 分页查询构建器
#[derive(Debug, Clone)]
pub struct PaginationBuilder {
    page_params: PageParams,
    sort_params: SortParams,
    search_params: SearchParams,
    filter_params: FilterParams,
}

impl PaginationBuilder {
    /// 创建分页构建器
    pub fn new() -> Self {
        Self {
            page_params: PageParams::default(),
            sort_params: SortParams::new(None, None),
            search_params: SearchParams::new(None, Vec::new()),
            filter_params: FilterParams::new(Vec::new()),
        }
    }
    
    /// 设置页码
    pub fn page(mut self, page: u32) -> Self {
        self.page_params.page = page;
        self
    }
    
    /// 设置每页大小
    pub fn page_size(mut self, page_size: u32) -> Self {
        self.page_params.page_size = page_size;
        self
    }
    
    /// 设置排序字段
    pub fn sort_by(mut self, sort_by: Option<String>) -> Self {
        self.sort_params.sort_by = sort_by;
        self
    }
    
    /// 设置排序方向
    pub fn sort_order(mut self, sort_order: Option<String>) -> Self {
        self.sort_params.sort_order = sort_order;
        self
    }
    
    /// 设置搜索关键词
    pub fn keyword(mut self, keyword: Option<String>) -> Self {
        self.search_params.keyword = keyword;
        self
    }
    
    /// 设置搜索字段
    pub fn search_fields(mut self, search_fields: Vec<String>) -> Self {
        self.search_params.search_fields = search_fields;
        self
    }
    
    /// 添加过滤条件
    pub fn add_filter(mut self, field: &str, operator: &str, value: serde_json::Value) -> Self {
        self.filter_params.add_filter(field, operator, value);
        self
    }
    
    /// 构建SQL查询
    pub fn build_sql(&self, table_name: &str) -> (String, String) {
        // 构建WHERE子句
        let mut where_clauses = Vec::new();
        
        if let Some(search_sql) = self.search_params.to_sql() {
            where_clauses.push(search_sql);
        }
        
      
        
        let where_clause = if where_clauses.is_empty() {
            "".to_string()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };
        
        // 构建ORDER BY子句
        let order_by_clause = self.sort_params.to_sql("created_at", "DESC");
        
        // 构建完整查询
        let count_sql = format!(
            "SELECT COUNT(*) FROM {} {}",
            table_name, where_clause
        );
        
        let query_sql = format!(
            "SELECT * FROM {} {} ORDER BY {} LIMIT {} OFFSET {}",
            table_name,
            where_clause,
            order_by_clause,
            self.page_params.limit(),
            self.page_params.offset()
        );
        
        (count_sql, query_sql)
    }
    
    /// 获取分页参数
    pub fn page_params(&self) -> &PageParams {
        &self.page_params
    }
    
    /// 获取排序参数
    pub fn sort_params(&self) -> &SortParams {
        &self.sort_params
    }
    
    /// 获取搜索参数
    pub fn search_params(&self) -> &SearchParams {
        &self.search_params
    }
    
    /// 获取过滤参数
    pub fn filter_params(&self) -> &FilterParams {
        &self.filter_params
    }
}

impl Default for PaginationBuilder {
    fn default() -> Self {
        Self::new()
    }
}


/// 分页结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
}

impl<T> PaginatedResult<T> {
    pub fn new(items: Vec<T>, total: u64, page: u64, per_page: u64) -> Self {
        let total_pages = (total as f64 / per_page as f64).ceil() as u64;
        
        Self {
            items,
            total,
            page,
            per_page,
            total_pages,
        }
    }
    
    pub fn has_next(&self) -> bool {
        self.page < self.total_pages
    }
    
    pub fn has_prev(&self) -> bool {
        self.page > 1
    }
    
    pub fn next_page(&self) -> Option<u64> {
        if self.has_next() {
            Some(self.page + 1)
        } else {
            None
        }
    }
    
    pub fn prev_page(&self) -> Option<u64> {
        if self.has_prev() {
            Some(self.page - 1)
        } else {
            None
        }
    }
}