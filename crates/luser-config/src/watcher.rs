use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{info, warn, error, debug};
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use crate::{AppConfig, ConfigError, ConfigManager, ConfigResult};

/// 配置监控器
#[derive(Debug)]
pub struct ConfigWatcher {
    config: Arc<RwLock<AppConfig>>,
    config_dir: PathBuf,
    watcher: Option<RecommendedWatcher>,
    reload_rx: Option<mpsc::Receiver<()>>,
    reload_tx: Option<mpsc::Sender<()>>,
    is_running: Arc<RwLock<bool>>,
}

impl ConfigWatcher {
    /// 创建新的配置监控器
    pub fn new(config: Arc<RwLock<AppConfig>>, config_dir: PathBuf) -> ConfigResult<Self> {
        let (reload_tx, reload_rx) = mpsc::channel(100);
        
        Ok(Self {
            config,
            config_dir,
            watcher: None,
            reload_rx: Some(reload_rx),
            reload_tx: Some(reload_tx),
            is_running: Arc::new(RwLock::new(false)),
        })
    }
    
    /// 启动监控
    pub fn start(&mut self) -> ConfigResult<()> {
        if *self.is_running.read() {
            warn!("配置监视器已经在运行");
            return Ok(());
        }
        
        let config_dir = self.config_dir.clone();
        let reload_tx = self.reload_tx.clone().unwrap();
        let is_running = self.is_running.clone();
        
        // 创建文件系统监控器
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    // 检查是否是配置文件变更
                    if Self::is_config_file_event(&event) {
                        debug!("检测到配置文件更改: {:?}", event);
                        
                        // 发送重载信号
                        let tx = reload_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = tx.send(()).await {
                                error!("发送重载信号失败: {}", e);
                            }
                        });
                    }
                }
                Err(e) => {
                    error!("配置文件监视器错误: {}", e);
                }
            }
        }).map_err(|e| ConfigError::WatchError(format!("创建监视器失败: {}", e)))?;
        
        // 监控配置目录
        watcher.watch(&config_dir, RecursiveMode::Recursive)
            .map_err(|e| ConfigError::WatchError(format!("无法监视配置目录: {}", e)))?;
        
        self.watcher = Some(watcher);
        *self.is_running.write() = true;
        
        info!("已启动目录配置监视器: {:?}", config_dir);
        
        Ok(())
    }
    
    /// 停止监控
    pub fn stop(&mut self) {
        *self.is_running.write() = false;
        self.watcher = None;
        info!("配置监视器已停止");
    }
    
    /// 检查事件是否是配置文件变更
    fn is_config_file_event(event: &Event) -> bool {
        // 检查事件类型
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                // 检查文件扩展名
                if let Some(path) = event.paths.first() {
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        return ext_str == "toml" || ext_str == "json" || ext_str == "yaml" || ext_str == "yml";
                    }
                }
                false
            }
            _ => false,
        }
    }
    
    /// 获取重载通道接收器
    pub fn get_reload_receiver(&mut self) -> Option<mpsc::Receiver<()>> {
        self.reload_rx.take()
    }
    
    /// 创建自动重载任务
    pub async fn start_auto_reload(
        config_manager: Arc<RwLock<ConfigManager>>,
        check_interval: Duration,
    ) -> ConfigResult<()> {
        info!("开始自动重新加载任务，间隔时间为: {:?}", check_interval);
        
        tokio::spawn(async move {
            let mut interval = time::interval(check_interval);
            
            loop {
                interval.tick().await;
                
                    
                let manager = config_manager.read();
                if manager.should_reload(check_interval.as_secs()) {
                    drop(manager);
                    
                    // 需要可变引用，所以重新获取
                    let mut manager = config_manager.write();
                    if let Err(e) = manager.reload() {
                        error!("自动重载失败: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
}

/// 数据库配置监控器
#[derive(Debug)]
pub struct DatabaseConfigWatcher {
    config_manager: Arc<RwLock<ConfigManager>>,
    check_interval: Duration,
    is_running: Arc<RwLock<bool>>,
}

impl DatabaseConfigWatcher {
    /// 创建新的数据库配置监控器
    pub fn new(config_manager: Arc<RwLock<ConfigManager>>, check_interval: Duration) -> Self {
        Self {
            config_manager,
            check_interval,
            is_running: Arc::new(RwLock::new(false)),
        }
    }
    
    /// 启动数据库配置监控
    pub async fn start(&self) -> ConfigResult<()> {
        if *self.is_running.read() {
            warn!("数据库配置监视器已经在运行");
            return Ok(());
        }
        
        *self.is_running.write() = true;
        
        let config_manager = self.config_manager.clone();
        let check_interval = self.check_interval;
        let is_running = self.is_running.clone();
        
        tokio::spawn(async move {
            let mut interval = time::interval(check_interval);
            
            while *is_running.read() {
                interval.tick().await;
                
                // 检查并重新加载数据库配置
                let mut manager = config_manager.write();
                if let Err(e) = manager.reload_database_config() {
                    error!("数据库配置重载失败: {}", e);
                }
            }
        });
        
        info!("数据库配置监视器已启动，间隔为: {:?}", check_interval);
        
        Ok(())
    }
    
    /// 停止数据库配置监控
    pub fn stop(&self) {
        *self.is_running.write() = false;
        info!("数据库配置监视器已停止");
    }
}

/// 密钥轮换监控器
#[derive(Debug)]
pub struct KeyRotationWatcher {
    config_manager: Arc<RwLock<ConfigManager>>,
    rotation_interval: Duration,
    is_running: Arc<RwLock<bool>>,
}

impl KeyRotationWatcher {
    /// 创建新的密钥轮换监控器
    pub fn new(config_manager: Arc<RwLock<ConfigManager>>, rotation_interval: Duration) -> Self {
        Self {
            config_manager,
            rotation_interval,
            is_running: Arc::new(RwLock::new(false)),
        }
    }
    
    /// 启动密钥轮换监控
    pub fn start(&self) -> ConfigResult<()> {
        if *self.is_running.read() {
            warn!("密钥轮换监控器已经在运行");
            return Ok(());
        }
        
        *self.is_running.write() = true;
        
        let config_manager = self.config_manager.clone();
        let rotation_interval = self.rotation_interval;
        let is_running = self.is_running.clone();
        
        // 使用 LocalSet 来运行非 Send 的任务
        tokio::task::spawn_local(async move {
            let mut interval = time::interval(rotation_interval);
            
            while *is_running.read() {
                interval.tick().await;
                
                // 检查是否需要轮换密钥
                let should_rotate = {
                    let manager = config_manager.read();
                    if let Some(encryptor) = manager.encryptor() {
                        if let Some(key_manager) = encryptor.key_manager() {
                            let key_manager_guard = key_manager.read();
                            key_manager_guard.should_rotate_key()
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };
                
                if should_rotate {
                    info!("检测到密钥需要轮换，开始轮换流程...");
                    
                    // 执行密钥轮换
                    let mut manager = config_manager.write();
                    match manager.rotate_key_with_database_update().await {
                        Ok(new_key_id) => {
                            info!("密钥轮换成功，新密钥ID: {}", new_key_id);
                            
                            // 重新加密数据库中的配置
                            if let Err(e) = manager.reencrypt_database_configs().await {
                                error!("重新加密数据库配置失败: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("密钥轮换失败: {}", e);
                        }
                    }
                }
            }
        });
        
        info!("密钥轮换监控器已启动，轮换间隔: {:?}", rotation_interval);
        Ok(())
    }
    
    /// 停止密钥轮换监控
    pub fn stop(&self) {
        *self.is_running.write() = false;
        info!("密钥轮换监控器已停止");
    }
}