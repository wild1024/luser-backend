#[cfg(test)]
mod tests {
    use crate::{ConfigResult, EncryptionAlgorithm};

    use super::*;
    use tempfile::NamedTempFile;
    use std::env;
    
    #[test]
    fn test_encryption_decryption() -> ConfigResult<()> {
        // 设置测试环境变量
        env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32]));
        
        // 创建加密管理器
        let encryption_manager = EncryptionManager::from_env(
            EncryptionAlgorithm::Aes256Gcm, 
            "GRAPE_ENCRYPTION_KEY"
        )?;
        
        let encryptor = ConfigEncryptor::new(encryption_manager);
        
        // 测试字符串加密解密
        let plaintext = "my_secret_password";
        let encrypted = encryptor.encrypt_config_value(
            "test.password",
            plaintext,
            ConfigSecurityLevel::Sensitive
        )?;
        
        assert!(encrypted.starts_with("ENC[sensitive:"));
        assert!(encrypted.ends_with(']'));
        
        let decrypted = encryptor.decrypt_config_value("test.password", &encrypted)?;
        assert_eq!(decrypted, plaintext);
        
        Ok(())
    }
    
    #[test]
    fn test_config_encryption() -> ConfigResult<()> {
        // 设置测试环境变量
        env::set_var("GRAPE_ENCRYPTION_KEY", base64::encode(vec![1u8; 32]));
        
        // 创建测试配置
        let mut config = AppConfig::default();
        config.database.url = "postgres://user:password@localhost:5432/db".to_string();
        config.redis.password = Some("redis_password".to_string());
        config.jwt.secret = "jwt_secret_key".to_string();
        
        // 初始化加密器
        init_global_encryptor()?;
        let encryptor = get_global_encryptor()?;
        
        // 加密配置
        encryptor.encrypt_config(&mut config)?;
        
        // 验证配置已加密
        assert!(config.database.url.starts_with("ENC[sensitive:"));
        assert!(config.redis.password.unwrap().starts_with("ENC[sensitive:"));
        assert!(config.jwt.secret.starts_with("ENC[secret:"));
        
        // 解密配置
        encryptor.decrypt_config(&mut config)?;
        
        // 验证配置已解密
        assert_eq!(config.database.url, "postgres://user:password@localhost:5432/db");
        assert_eq!(config.redis.password, Some("redis_password".to_string()));
        assert_eq!(config.jwt.secret, "jwt_secret_key");
        
        Ok(())
    }
    
    #[test]
    fn test_database_url_encryption() -> ConfigResult<()> {
        env::set_var("GRAPE_ENCRYPTION_KEY", base64::encode(vec![1u8; 32]));
        init_global_encryptor()?;
        let encryptor = get_global_encryptor()?;
        
        // 测试数据库URL加密
        let url = "postgres://admin:secret123@localhost:5432/mydb";
        let encrypted = encryptor.encrypt_database_url(url)?;
        
        assert!(encrypted.contains("ENC[sensitive:"));
        
        let decrypted = encryptor.decrypt_database_url(&encrypted)?;
        assert_eq!(decrypted, url);
        
        Ok(())
    }
    
    #[test]
    fn test_config_manager_encryption() -> ConfigResult<()> {
        env::set_var("GRAPE_ENCRYPTION_KEY", base64::encode(vec![1u8; 32]));
        
        // 创建临时配置文件
        let mut temp_file = NamedTempFile::new()?;
        let config_content = r#"
            [database]
            url = "postgres://user:password@localhost:5432/db"
            
            [redis]
            password = "redis_pass"
            
            [jwt]
            secret = "jwt_secret"
        "#;
        
        std::fs::write(temp_file.path(), config_content)?;
        
        // 使用ConfigManager加载配置
        let mut manager = ConfigManager::new()?;
        
        // 获取配置并验证
        let config = manager.get_config();
        
        // 导出加密配置
        let export_path = temp_file.path().with_extension("encrypted.toml");
        manager.export_to_file(&export_path)?;
        
        // 读取导出的文件验证加密
        let exported_content = std::fs::read_to_string(&export_path)?;
        assert!(exported_content.contains("ENC["));
        
        // 导入加密配置
        manager.import_from_file(&export_path)?;
        
        Ok(())
    }
    
    #[test]
    fn test_key_rotation() -> ConfigResult<()> {
        env::set_var("GRAPE_ENCRYPTION_KEY", base64::encode(vec![1u8; 32]));
        
        let encryption_manager = EncryptionManager::from_env(
            EncryptionAlgorithm::Aes256Gcm, 
            "GRAPE_ENCRYPTION_KEY"
        )?;
        
        // 生成新密钥
        let new_key = EncryptionManager::generate_key(EncryptionAlgorithm::Aes256Gcm)?;
        
        // 轮换密钥
        encryption_manager.rotate_key(new_key.clone())?;
        
        // 验证新密钥
        let current_key = encryption_manager.get_base64_key();
        assert_eq!(current_key, base64::encode(&new_key));
        
        Ok(())
    }
}