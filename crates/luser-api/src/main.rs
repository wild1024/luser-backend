
use std::env;
use tracing::{info, error, Level};
use tracing_subscriber;
pub mod routers;
pub mod handlers;
pub mod middleware;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 初始化日志
    init_logging();
    print_startup_banner();
    
    Ok(())
   
    
    
}

/// 初始化日志系统
fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        
        .init();
}

/// 打印启动横幅
fn print_startup_banner() {
    println!(
        r#"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║      LUSER 视频付费订阅网站后端服务                      ║
║                                                          ║
║      版本:                                               ║
║      作者: HWPE 团队                                     ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"#
        
    );
}
