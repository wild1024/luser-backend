数据库模块采用类似JFinal ActiveRecord的设计思想，实现全局数据库连接池管理和链式调用API，让调用更加简单易用。

## 1. 数据库模块结构

```
crates/luser-db/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── global.rs          # 全局数据库管理
│   ├── pool.rs           # 连接池管理
│   ├── model.rs          # Model基类和宏
│   ├── db.rs            # Db类，提供链式调用
│   ├── query.rs         # 查询构建器
│   ├── transaction.rs    # 事务管理
│   ├── pagination.rs     # 分页支持
│   ├── error.rs         # 错误类型
│   ├── enums.rs         # 枚举定义
│   ├── types.rs         # 自定义类型
│   ├── migrator.rs      # 迁移管理
│   └── macros/          # 过程宏
│       ├── mod.rs
│       ├── model.rs     # Model宏
│       └── column.rs    # Column宏
└── migrations/              # 迁移文件
   
```



## 2. 使用示例

### `examples/user_example.rs`
```rust
use luser_db::{
    define_model, model, query,
    global::{init_from_env, db},
    enums::{UserRole, UserStatus},
};
use serde_json::json;
use chrono::Utc;

// 定义User模型
define_model! {
    User {
        id: uuid::Uuid,
        username: String,
        email: String,
        password_hash: String,
        display_name: Option<String>,
        role: UserRole,
        status: UserStatus,
        created_at: chrono::DateTime<Utc>,
        updated_at: chrono::DateTime<Utc>,
        deleted_at: Option<chrono::DateTime<Utc>>,
    }
}

// 实现自定义方法
impl User {
    pub fn new(username: String, email: String, password: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            username,
            email,
            password_hash: format!("hashed_{}", password), // 实际项目中使用argon2或bcrypt
            display_name: None,
            role: UserRole::User,
            status: UserStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }
    
    pub async fn find_by_username(username: &str) -> Option<Self> {
        User::find_first(Some("username = $1"), Some(&[json!(username)]))
            .await
            .ok()
            .flatten()
    }
    
    pub async fn find_active_users() -> Vec<Self> {
        User::find_all(Some("status = 'active' AND deleted_at IS NULL"), None)
            .await
            .unwrap_or_default()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 初始化数据库
    init_db().await?;
    println!("数据库初始化完成");
    
    // 2. 创建用户（方法1：使用Model trait）
    let mut user = User::new(
        "johndoe".to_string(),
        "john@example.com".to_string(),
        "password123".to_string(),
    );
    
    user.save().await?;
    println!("创建用户: {:?}", user);
    
    // 3. 查询用户（方法2：使用Db链式调用）
    let found_user = User::db()
        .where_param("username = $1", json!("johndoe"))
        .fetch_one()
        .await?;
    
    println!("查询用户: {:?}", found_user);
    
    // 4. 使用查询构建器
    let users = query::<User>()
        .select("id, username, email")
        .where_param("status = $1", json!("active"))
        .order_by("created_at DESC")
        .limit(10)
        .fetch_all()
        .await?;
    
    println!("查询活跃用户: {}个", users.len());
    
    // 5. 更新用户
    if let Some(mut user) = found_user {
        user.display_name = Some("John Doe".to_string());
        user.update().await?;
        println!("更新用户完成");
    }
    
    // 6. 分页查询
    let page_result = User::paginate(1, 20, None).await?;
    println!("分页结果: 第{}页，共{}条，总计{}条", 
        page_result.page, page_result.items.len(), page_result.total);
    
    // 7. 删除用户
    let deleted_count = User::db()
        .delete_by_id(user.id)
        .await?;
    println!("删除用户: {}条", deleted_count);
    
    // 8. 执行事务
    use luser_db::transaction;
    
    let result = transaction!({
        // 在事务中执行多个操作
        let mut user1 = User::new(
            "user1".to_string(),
            "user1@example.com".to_string(),
            "password123".to_string(),
        );
        
        user1.save().await?;
        
        let mut user2 = User::new(
            "user2".to_string(),
            "user2@example.com".to_string(),
            "password456".to_string(),
        );
        
        user2.save().await?;
        
        Ok::<(User, User), luser_db::error::DatabaseError>((user1, user2))
    }).await?;
    
    println!("事务执行成功，创建用户: {} 和 {}", result.0.username, result.1.username);
    
    // 9. 使用全局db函数
    let user_count = db().query::<User>()
        .where_param("status = $1", json!("active"))
        .count()
        .await?;
    
    println!("活跃用户数量: {}", user_count);
    
    Ok(())
}
```

### `examples/video_example.rs`
```rust
use luser_db::{
    define_model, model, query,
    global::init_from_env,
    enums::{VideoStatus, VideoVisibility},
};
use serde_json::json;
use chrono::Utc;

// 定义Video模型
define_model! {
    Video {
        id: uuid::Uuid,
        author_id: uuid::Uuid,
        title: String,
        description: Option<String>,
        duration_seconds: i32,
        file_size: i64,
        status: VideoStatus,
        visibility: VideoVisibility,
        price_amount: rust_decimal::Decimal,
        currency: String,
        view_count: i64,
        like_count: i64,
        tags: Option<Vec<String>>,
        published_at: Option<chrono::DateTime<Utc>>,
        created_at: chrono::DateTime<Utc>,
        updated_at: chrono::DateTime<Utc>,
        deleted_at: Option<chrono::DateTime<Utc>>,
    }
}

impl Video {
    pub fn new(author_id: uuid::Uuid, title: String, duration: i32, file_size: i64) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            author_id,
            title,
            description: None,
            duration_seconds: duration,
            file_size,
            status: VideoStatus::Draft,
            visibility: VideoVisibility::Private,
            price_amount: rust_decimal::Decimal::from(0),
            currency: "CNY".to_string(),
            view_count: 0,
            like_count: 0,
            tags: None,
            published_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }
    
    pub fn set_published(&mut self) {
        self.status = VideoStatus::Published;
        self.visibility = VideoVisibility::Public;
        self.published_at = Some(Utc::now());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化数据库
    init_from_env().await?;
    
    let author_id = uuid::Uuid::new_v4();
    
    // 创建视频
    let mut video = Video::new(
        author_id,
        "Rust编程教程".to_string(),
        3600, // 1小时
        1024 * 1024 * 500, // 500MB
    );
    
    video.description = Some("这是一门关于Rust编程语言的教程".to_string());
    video.tags = Some(vec!["编程".to_string(), "Rust".to_string(), "教程".to_string()]);
    video.price_amount = rust_decimal::Decimal::from(999); // 9.99元
    video.set_published();
    
    video.save().await?;
    println!("创建视频: {}", video.title);
    
    // 查询作者的所有视频
    let author_videos = query::<Video>()
        .where_param("author_id = $1", json!(author_id))
        .where_param("status = $2", json!("published"))
        .order_by("created_at DESC")
        .fetch_all()
        .await?;
    
    println!("作者视频数量: {}", author_videos.len());
    
    // 复杂查询：标签搜索 + 分页
    let tagged_videos = query::<Video>()
        .select("id, title, author_id, view_count, like_count, tags")
        .where_param("status = $1", json!("published"))
        .where_param("visibility = $2", json!("public"))
        .where_param("tags @> $3", json!(["Rust"])) // PostgreSQL数组包含查询
        .order_by("view_count DESC")
        .paginate(1, 10)
        .fetch_paginated(1, 10)
        .await?;
    
    println!("Rust相关视频: {}个", tagged_videos.items.len());
    
    // 批量更新：增加视频观看次数
    let update_count = query::<Video>()
        .where_param("author_id = $1", json!(author_id))
        .where_param("status = $2", json!("published"))
        .update(&[
            ("view_count".to_string(), json!("view_count + 1")),
        ].iter().cloned().collect())
        .await?;
    
    println!("更新了 {} 个视频的观看次数", update_count);
    
    // 统计视频数据
    let stats = query::<Video>()
        .select("COUNT(*) as total, SUM(view_count) as total_views, AVG(duration_seconds) as avg_duration")
        .where_param("status = $1", json!("published"))
        .fetch_one::<(i64, Option<i64>, Option<f64>)>() // 自定义返回类型
        .await?;
    
    println!("视频统计: 总数={}, 总观看数={:?}, 平均时长={:?}秒", 
        stats.0, stats.1, stats.2);
    
    Ok(())
}
```

## 3. Cargo.toml

```toml
[package]
name = "luser-db"
version = "0.1.0"
edition = "2024"
description = "Enhanced database module with ActiveRecord pattern for LUSER"

[dependencies]
luser-config = { path = "../luser-config" }
luser-common = { path = "../luser-common" }
tracing = { workspace = true}
thiserror = { workspace = true}
chrono = { workspace = true}
sqlx ={ workspace = true }
tokio = { workspace = true}
serde =  { workspace = true}
serde_json =  { workspace = true}
bigdecimal = { workspace = true}
uuid = { workspace = true}
sha2= { workspace = true}
once_cell = "1.0"
async-trait = {workspace = true}
[dev-dependencies]
dotenv = "0.15"

[features]
default = ["sqlx/runtime-tokio-native-tls"]
global = []  # 启用全局数据库功能
model-macros = []  # 启用模型宏
migrate = []  # 启用迁移功能
test = []  # 启用测试功能
```

## 4. 主文件

### `src/lib.rs`
```rust
//! LUSER 数据库模块（优化版）
//! 
//! 提供全局数据库管理、ActiveRecord模式、链式调用API

pub mod global;
pub mod model;
pub mod db;
pub mod query;
pub mod transaction;
pub mod pagination;
pub mod error;
pub mod enums;
pub mod types;
pub mod migrator;

// 条件编译模块
#[cfg(feature = "global")]
pub use global::*;

#[cfg(feature = "model-macros")]
pub mod macros;

// 重新导出常用类型
pub use model::{Model, BaseModel, BaseModelWithId};
pub use db::Db;
pub use query::QueryBuilder;
pub use transaction::{TransactionManager, execute_transaction};
pub use pagination::PaginatedResult;
pub use error::DatabaseError;

/// 数据库初始化
pub async fn init() -> Result<(), DatabaseError> {
    #[cfg(feature = "global")]
    {
        global::init_from_env().await?;
    }
    
    Ok(())
}

/// 便捷宏：定义模型
#[macro_export]
macro_rules! define_model {
    ($($tt:tt)*) => {
        $crate::model::define_model!($($tt)*)
    };
}

/// 便捷函数：查询构建
pub fn query<T: Model>() -> QueryBuilder<T> {
    #[cfg(feature = "global")]
    {
        global::query::<T>()
    }
    #[cfg(not(feature = "global"))]
    {
        panic!("Global feature must be enabled to use query() function")
    }
}

/// 便捷函数：获取模型实例
pub fn model<T: Model>() -> T {
    T::default()
}

/// 便捷函数：执行原始SQL
pub async fn execute_sql(sql: &str) -> Result<u64, DatabaseError> {
    #[cfg(feature = "global")]
    {
        global::execute(sql).await
    }
    #[cfg(not(feature = "global"))]
    {
        panic!("Global feature must be enabled to use execute_sql() function")
    }
}
```

## 5. 核心优势

1. **全局单例管理**：类似于JFinal的ActiveRecord，通过`db()`全局函数访问数据库
2. **链式调用**：提供流畅的链式API，类似Builder模式
3. **简化CRUD**：通过Model trait提供基础的CRUD操作
4. **事务支持**：提供便捷的事务管理API
5. **类型安全**：利用Rust的类型系统确保查询安全
6. **性能优化**：连接池管理和查询优化
7. **易于扩展**：支持自定义查询和复杂操作

## 6. 使用对比

### 传统方式
```rust
let user = user_repository.find_by_id(user_id).await?;
user_repository.update(user).await?;
```

### 优化后方式
```rust
// 方法1：使用Model trait
let mut user = User::find_by_id(user_id).await?.unwrap();
user.username = "new_username".to_string();
user.update().await?;

// 方法2：使用Db链式调用
User::db()
    .where_param("id = $1", json!(user_id))
    .update(&[("username".to_string(), json!("new_username"))])
    .await?;

// 方法3：使用查询构建器
query::<User>()
    .where_param("id = $1", json!(user_id))
    .update(&[("username".to_string(), json!("new_username"))])
    .await?;
```

这个优化后的数据库模块设计借鉴了JFinal ActiveRecord和Laravel Eloquent的思想，提供了更加简单、直观的数据库操作API，同时保持了Rust的类型安全和性能优势。