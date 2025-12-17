// use tracing::{subscriber::set_global_default, Level};
// use tracing_appender::{non_blocking, rolling};
// use tracing_subscriber::{EnvFilter, Layer, Registry, fmt, layer::SubscriberExt};

// /// 初始化日志系统
// pub fn init_logger(
//     log_level: Level,
//     log_dir: &str,
//     enable_json: bool,
//     enable_file: bool,
//     enable_console: bool,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     // 创建环境过滤器
//     let env_filter = EnvFilter::try_from_default_env()
//         .unwrap_or_else(|_| EnvFilter::new(format!("{}", log_level)));
    
//     // 创建控制台输出层
//     let console_layer = if enable_console {
//         let layer = fmt::layer()
//             .with_writer(std::io::stdout)
//             .with_target(true)
//             .with_thread_ids(true)
//             .with_thread_names(true)
//             .with_line_number(true)
//             .with_file(true);
        
//         if enable_json {
//             Some(layer.json().with_filter(env_filter.clone()))
//         } else {
//             Some(layer.with_filter(env_filter.clone()))
//         }
//     } else {
//         None
//     };
    
//     // 创建文件输出层
//     let file_layer = if enable_file {
//         let file_appender = rolling::daily(log_dir, "luser.log");
//         let (non_blocking_writer, _guard) = non_blocking(file_appender);
        
//         let layer = fmt::layer()
//             .with_writer(non_blocking_writer)
//             .with_ansi(false)
//             .with_target(true)
//             .with_thread_ids(true)
//             .with_thread_names(true)
//             .with_line_number(true)
//             .with_file(true);
        
//         if enable_json {
//             Some(layer.json().with_filter(env_filter.clone()))
//         } else {
//             Some(layer.with_filter(env_filter.clone()))
//         }
//     } else {
//         None
//     };
    
//     // 注册订阅者
//     let subscriber = Registry::default()
//         .with(console_layer)
//         .with(file_layer);
    
//     set_global_default(subscriber)?;
    
//     Ok(())
// }

// /// 结构化日志字段
// #[derive(Debug, Clone)]
// pub struct LogContext {
//     pub trace_id: String,
//     pub span_id: String,
//     pub user_id: Option<String>,
//     pub request_id: Option<String>,
//     pub ip_address: Option<String>,
//     pub user_agent: Option<String>,
//     pub path: Option<String>,
//     pub method: Option<String>,
// }

// impl LogContext {
//     pub fn new(trace_id: String) -> Self {
//         Self {
//             trace_id,
//             span_id: "".to_string(),
//             user_id: None,
//             request_id: None,
//             ip_address: None,
//             user_agent: None,
//             path: None,
//             method: None,
//         }
//     }
    
//     pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
//         self.user_id = Some(user_id.into());
//         self
//     }
    
//     pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
//         self.request_id = Some(request_id.into());
//         self
//     }
    
//     pub fn with_ip_address(mut self, ip_address: impl Into<String>) -> Self {
//         self.ip_address = Some(ip_address.into());
//         self
//     }
    
//     pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
//         self.user_agent = Some(user_agent.into());
//         self
//     }
    
//     pub fn with_path(mut self, path: impl Into<String>) -> Self {
//         self.path = Some(path.into());
//         self
//     }
    
//     pub fn with_method(mut self, method: impl Into<String>) -> Self {
//         self.method = Some(method.into());
//         self
//     }
// }

// /// 生成追踪ID
// pub fn generate_trace_id() -> String {
//     use uuid::Uuid;
//     format!("trace-{}", Uuid::new_v4())
// }

// /// 生成请求ID
// pub fn generate_request_id() -> String {
//     use rand::Rng;
//     let mut rng = rand::rng();
//     let random_number: u32 = rng.random();
//     format!(
//         "{}-{}",
//         chrono::Utc::now().timestamp_millis(),
//         random_number
//     )
// }