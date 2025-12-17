use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use rand::{ Rng, distr::Alphanumeric};
use ring::{hmac, rand::{self as ring_rand, SecureRandom}};
use sha2::{Digest, Sha256};

/// 使用Argon2哈希密码
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// 验证密码
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(hash) => hash,
        Err(_) => return false,
    };
    
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// 生成随机令牌
pub fn generate_token(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}



/// SHA256哈希
pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// HMAC SHA256签名
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    hex::encode(tag.as_ref())
}


/// 生成安全随机字节
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let rng = ring_rand::SystemRandom::new();
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes).unwrap();
    bytes
}
/// 生成验证码
pub fn generate_verification_code(length: usize) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| rng.random_range(0..10).to_string())
        .collect()
}

/// 生成安全的文件名
pub fn generate_filename(extension: &str) -> String {
    let timestamp = chrono::Utc::now().timestamp_millis();
    let random: u32 = rand::rng().random();
    format!("{}_{:x}.{}", timestamp, random, extension)
}