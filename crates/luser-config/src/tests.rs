#[cfg(test)]
mod tests {
    use crate::AppConfig;
    use crate::ConfigEncryptor;
    use crate::ConfigManager;
    use crate::ConfigResult;
    use crate::ConfigSecurityLevel;
    use crate::EncryptionAlgorithm;
    use crate::EncryptionManager;
    use crate::get_global_encryptor;
    use crate::init_global_encryptor;
    use std::env;
    use tempfile::NamedTempFile;

    #[test]
    fn test_encryption_decryption() -> ConfigResult<()> {
        // 设置测试环境变量
        unsafe { env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

        // 创建加密管理器
        let encryption_manager =
            EncryptionManager::from_env(EncryptionAlgorithm::Aes256Gcm, "LUSER_ENCRYPTION_KEY")?;

        let encryptor = ConfigEncryptor::new(encryption_manager);

        // 测试字符串加密解密
        let plaintext = "my_secret_password";
        let encrypted = encryptor.encrypt_config_value(
            "test.password",
            plaintext,
            ConfigSecurityLevel::Sensitive,
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
        unsafe { std::env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

        // 创建测试配置
        let mut config = crate::AppConfig::default();
        config.database.url = "postgres://user:password@localhost:5432/db".to_string();
        config.redis.password = Some("redis_password".to_string());
        config.jwt.secret = "jwt_secret_key".to_string();

        // 初始化加密器
        init_global_encryptor()?;
        let encryptor = get_global_encryptor()?;

        // 保存原始值
        let original_db_url = config.database.url.clone();
        let original_redis_password = config.redis.password.clone();
        let original_jwt_secret = config.jwt.secret.clone();

        println!("\n=== 开始测试 ===");
        println!("原始数据库URL: {}", original_db_url);

        // 测试1: 单独测试数据库URL加密/解密
        println!("\n1. 测试数据库URL加密/解密:");
        let encrypted_url = encryptor.encrypt_database_url(&original_db_url)?;
        println!("加密后URL: {}", encrypted_url);

        let decrypted_url = encryptor.decrypt_database_url(&encrypted_url)?;
        println!("解密后URL: {}", decrypted_url);
        assert_eq!(decrypted_url, original_db_url, "数据库URL解密失败");

        // 测试2: 加密整个配置
        println!("\n2. 加密整个配置:");
        encryptor.encrypt_config(&mut config)?;

        println!("加密后数据库URL: {}", config.database.url);

        // 验证配置已加密
        assert_ne!(config.database.url, original_db_url);
        assert!(
            config.database.url.contains("ENC%5B")
                || encryptor.is_encrypted_value(&config.database.url)
        );

        if let Some(ref redis_password) = config.redis.password {
            assert!(redis_password.starts_with("ENC[sensitive:"));
        }

        assert!(config.jwt.secret.starts_with("ENC[secret:"));

        // 测试3: 解密整个配置
        println!("\n3. 解密整个配置:");
        encryptor.decrypt_config(&mut config)?;

        println!("解密后数据库URL: {}", config.database.url);

        // 验证配置已正确解密
        assert_eq!(config.database.url, original_db_url, "数据库URL解密失败");
        assert_eq!(
            config.redis.password, original_redis_password,
            "Redis密码解密失败"
        );
        assert_eq!(config.jwt.secret, original_jwt_secret, "JWT密钥解密失败");

        println!("\n=== 测试通过 ===");

        Ok(())
    }

    #[test]
    fn test_database_url_encryption_decryption() -> ConfigResult<()> {
        unsafe { std::env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

        init_global_encryptor()?;
        let encryptor = get_global_encryptor()?;

        let test_cases = vec![
            // (url, should_be_encrypted)
            ("postgres://user:password@localhost:5432/db", true),
            ("postgres://admin:admin123@localhost:5432/testdb", true),
            ("mysql://user:pass%40word@localhost:3306/mydb", true), // @编码为%40
            ("postgres://user:pass%2Fword@localhost:5432/db", true), // /编码为%2F
            ("postgres://user:pass%3Aword@localhost:5432/db", true), // :编码为%3A
            ("postgres://user:@localhost:5432/db", false),          // 空密码，不应加密
            ("postgres://user@localhost:5432/db", false),           // 无密码，不应加密
        ];

        for (i, (url, should_be_encrypted)) in test_cases.iter().enumerate() {
            println!("\n测试 {}: {}", i + 1, url);

            // 加密
            let encrypted = encryptor.encrypt_database_url(url)?;
            println!("加密后: {}", encrypted);

            if *should_be_encrypted {
                assert_ne!(encrypted, *url, "URL应该被加密但未被加密");
            }

            // 解密
            let decrypted = encryptor.decrypt_database_url(&encrypted)?;
            println!("解密后: {}", decrypted);

            // 验证解密后与原始相同
            assert_eq!(decrypted, *url, "测试 {} 失败: URL解密后不匹配", i + 1);
        }

        println!("\n所有数据库URL加密/解密测试通过！");
        Ok(())
    }
   

    #[test]
    fn test_config_manager_encryption() -> ConfigResult<()> {
        unsafe { env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

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
        unsafe { env::set_var("LUSER_ENCRYPTION_KEY", base64::encode(vec![1u8; 32])) };

        let encryption_manager =
            EncryptionManager::from_env(EncryptionAlgorithm::Aes256Gcm, "LUSER_ENCRYPTION_KEY")?;

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
