use luser_config::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 设置加密密钥
    unsafe { std::env::set_var("LUSER_ENCRYPTION_KEY", "your-32-byte-base64-encoded-key") };
    
    // 1. 加载并自动解密配置
    let config = AppConfig::from_file("./config/production.encrypted.toml")?;
    
    // 2. 获取解密后的敏感信息
    let db_url = config.get_decrypted_database_url()?;
    let jwt_secret = config.get_decrypted_jwt_secret()?;
    let redis_password = config.get_decrypted_redis_password()?;
    
    // 3. 加密配置并保存
    let mut config_for_export = config.clone();
    config_for_export.encrypt_sensitive_fields()?;
    
    // 4. 使用配置管理器
    let mut manager = ConfigManager::new()?;
    
    // 获取加密版本的配置值（用于日志等）
    let encrypted_jwt = manager.get_encrypted_value("jwt.secret")?;
    
    // 导出加密配置
    manager.export_to_file("./config/exported.encrypted.toml")?;
    
    // 5. 密钥轮换
    init_global_encryptor()?;
    let encryptor = get_global_encryptor()?;
    // let key_manager = encryptor.encryption_manager().key_manager();
    
    // if key_manager.should_rotate_key() {
    //     let new_key_id = key_manager.rotate_key()?;
    //     println!("Key rotated successfully: {}", new_key_id);
    // }
    
    Ok(())
}