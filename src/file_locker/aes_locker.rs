use super::base::Locker;
use std::path::PathBuf;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;
use async_trait::async_trait;
use tokio::fs;

const SALT_LENGTH: usize = 16;
const IV_LENGTH: usize = 16;
const KEY_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32;
const BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AesLocker;

impl AesLocker {
    pub fn new() -> Self {
        AesLocker
    }

    /// 从密码和盐派生加密密钥
    fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
        let mut key = [0u8; KEY_LENGTH];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, KEY_ITERATIONS, &mut key);
        key
    }

    /// 加密数据：返回 salt + iv + encrypted_data
    fn encrypt_data(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
        // 生成随机盐和IV
        let mut rng = rand::rng();
        let salt: [u8; SALT_LENGTH] = rng.random();
        let iv: [u8; IV_LENGTH] = rng.random();

        // 派生密钥
        let key = Self::derive_key(password, &salt);

        // 创建cipher
        let cipher = Aes256::new(GenericArray::from_slice(&key));

        // 对数据进行PKCS7填充
        let padded_data = Self::add_pkcs7_padding(data);

        // 按16字节块加密（AES-CBC手动实现）
        let mut encrypted = vec![0u8; padded_data.len()];
        let mut prev_block = iv;

        for (i, chunk) in padded_data.chunks(BLOCK_SIZE).enumerate() {
            let mut block = GenericArray::from_slice(chunk).clone();
            
            // CBC模式：与前一个密文块进行XOR
            for j in 0..BLOCK_SIZE {
                block[j] ^= prev_block[j];
            }
            
            // 加密块
            cipher.encrypt_block(&mut block);
            
            // 将加密后的块复制到结果中
            let start = i * BLOCK_SIZE;
            encrypted[start..start + BLOCK_SIZE].copy_from_slice(&block);
            prev_block = block.to_vec().try_into().unwrap();
        }

        // 组合结果: salt + iv + encrypted_data
        let mut result = Vec::with_capacity(SALT_LENGTH + IV_LENGTH + encrypted.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&iv);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    /// 解密数据：从 salt + iv + encrypted_data 中恢复原始数据
    fn decrypt_data(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>, String> {
        if encrypted_data.len() < SALT_LENGTH + IV_LENGTH {
            return Err("Data too short".to_string());
        }

        // 提取salt、iv和实际加密数据
        let salt = &encrypted_data[0..SALT_LENGTH];
        let iv = &encrypted_data[SALT_LENGTH..SALT_LENGTH + IV_LENGTH];
        let encrypted = &encrypted_data[SALT_LENGTH + IV_LENGTH..];

        // 派生密钥
        let key = Self::derive_key(password, salt);

        // 创建cipher
        let cipher = Aes256::new(GenericArray::from_slice(&key));

        // 按16字节块解密（AES-CBC手动实现）
        let mut decrypted = vec![0u8; encrypted.len()];
        let mut prev_block = iv.to_vec();

        for (i, chunk) in encrypted.chunks(BLOCK_SIZE).enumerate() {
            let mut block = GenericArray::from_slice(chunk).clone();
            let block_copy = block.to_vec();
            
            // 解密块
            cipher.decrypt_block(&mut block);
            
            // CBC模式：与前一个密文块进行XOR
            for j in 0..BLOCK_SIZE {
                block[j] ^= prev_block[j];
            }
            
            // 将解密后的块复制到结果中
            let start = i * BLOCK_SIZE;
            decrypted[start..start + BLOCK_SIZE].copy_from_slice(&block);
            prev_block = block_copy;
        }

        // 移除PKCS7填充
        let unpadded_data = Self::remove_pkcs7_padding(&decrypted)
            .map_err(|_| "Decryption failed: Invalid padding".to_string())?;

        Ok(unpadded_data)
    }

    /// PKCS7填充
    fn add_pkcs7_padding(data: &[u8]) -> Vec<u8> {
        let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
        let mut padded = data.to_vec();
        padded.extend(vec![padding_len as u8; padding_len]);
        padded
    }

    /// 移除PKCS7填充
    fn remove_pkcs7_padding(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() {
            return Err("Empty data".to_string());
        }

        let padding_len = data[data.len() - 1] as usize;

        if padding_len > BLOCK_SIZE || padding_len == 0 {
            return Err("Invalid padding length".to_string());
        }

        if data.len() < padding_len {
            return Err("Data shorter than padding length".to_string());
        }

        // 验证所有填充字节
        for i in 0..padding_len {
            if data[data.len() - 1 - i] != padding_len as u8 {
                return Err("Invalid padding".to_string());
            }
        }

        Ok(data[..data.len() - padding_len].to_vec())
    }
}

impl Default for AesLocker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Locker for AesLocker {
    fn locker_id(&self) -> [u8; 4] {
        *b"AES\0"
    }

    async fn lock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        // 读取原始文件内容
        let original_data = fs::read(&filepath).await?;

        // 加密数据
        let encrypted_data =
            Self::encrypt_data(&original_data, &password).map_err(|e| {
                tokio::io::Error::new(tokio::io::ErrorKind::Other, e)
            })?;

        // 写入加密后的数据
        fs::write(&filepath, encrypted_data).await?;

        Ok(())
    }

    async fn unlock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        // 读取加密文件内容
        let encrypted_data = fs::read(&filepath).await?;

        // 解密数据
        let decrypted_data = Self::decrypt_data(&encrypted_data, &password).map_err(|e| {
            tokio::io::Error::new(tokio::io::ErrorKind::Other, e)
        })?;

        // 写入解密后的数据
        fs::write(&filepath, decrypted_data).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = "test_password";
        let salt1 = [1u8; SALT_LENGTH];
        let salt2 = [2u8; SALT_LENGTH];

        let key1 = AesLocker::derive_key(password, &salt1);
        let key2 = AesLocker::derive_key(password, &salt2);

        // 相同的密码和盐应该生成相同的密钥
        assert_eq!(key1, AesLocker::derive_key(password, &salt1));

        // 不同的盐应该生成不同的密钥
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "my_secure_password";
        let original_data = b"Hello, World! This is a test message.";

        // 加密
        let encrypted = AesLocker::encrypt_data(original_data, password)
            .expect("Encryption failed");

        // 验证结构：salt + iv + encrypted_data
        assert!(encrypted.len() > SALT_LENGTH + IV_LENGTH);

        // 解密
        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");

        // 验证解密后的数据与原始数据一致
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let password = "password";
        let original_data = b"";

        let encrypted = AesLocker::encrypt_data(original_data, password)
            .expect("Encryption failed");

        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let password = "large_data_password";
        let original_data = vec![42u8; 1024 * 100]; // 100KB

        let encrypted = AesLocker::encrypt_data(&original_data, password)
            .expect("Encryption failed");

        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_wrong_password_fails() {
        let original_data = b"Secret message";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = AesLocker::encrypt_data(original_data, password)
            .expect("Encryption failed");

        // 用错误的密码解密应该失败
        let result = AesLocker::decrypt_data(&encrypted, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_data_fails() {
        let password = "password";
        let original_data = b"Test data";

        let mut encrypted = AesLocker::encrypt_data(original_data, password)
            .expect("Encryption failed");

        // 修改加密数据
        if encrypted.len() > SALT_LENGTH + IV_LENGTH {
            encrypted[SALT_LENGTH + IV_LENGTH] ^= 0xFF;
        }

        // 解密修改后的数据应该失败或产生不同的结果
        let result = AesLocker::decrypt_data(&encrypted, password);
        // 可能成功但内容不同，或直接失败
        if let Ok(decrypted) = result {
            assert_ne!(decrypted, original_data);
        }
    }

    #[test]
    fn test_different_encryptions_different_results() {
        let password = "password";
        let data = b"Test data";

        let encrypted1 = AesLocker::encrypt_data(data, password)
            .expect("First encryption failed");
        let encrypted2 = AesLocker::encrypt_data(data, password)
            .expect("Second encryption failed");

        // 由于使用了随机的盐和IV，两次加密结果应该不同
        assert_ne!(encrypted1, encrypted2);

        // 但两个都能用同一个密码正确解密
        let decrypted1 = AesLocker::decrypt_data(&encrypted1, password)
            .expect("First decryption failed");
        let decrypted2 = AesLocker::decrypt_data(&encrypted2, password)
            .expect("Second decryption failed");

        assert_eq!(decrypted1, data);
        assert_eq!(decrypted2, data);
    }

    #[test]
    fn test_binary_data_encryption() {
        let password = "binary_password";
        let original_data: Vec<u8> = (0..=255).collect();

        let encrypted = AesLocker::encrypt_data(&original_data, password)
            .expect("Encryption failed");

        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_locker_id() {
        let locker = AesLocker::new();
        let id = locker.locker_id();
        assert_eq!(id, *b"AES\0");
    }

    #[test]
    fn test_default_implementation() {
        let locker1 = AesLocker::new();
        let locker2 = AesLocker::default();
        let id1 = locker1.locker_id();
        let id2 = locker2.locker_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_pkcs7_padding() {
        let data1 = vec![1, 2, 3];
        let padded1 = AesLocker::add_pkcs7_padding(&data1);
        assert_eq!(padded1.len(), 16);
        assert_eq!(padded1[3], 13); // 填充13字节

        let data2 = vec![1; 16];
        let padded2 = AesLocker::add_pkcs7_padding(&data2);
        assert_eq!(padded2.len(), 32); // 完整块需要添加一个完整的填充块
        assert_eq!(padded2[16], 16); // 填充16字节
    }

    #[test]
    fn test_pkcs7_padding_removal() {
        let data = vec![1, 2, 3];
        let padded = AesLocker::add_pkcs7_padding(&data);
        let unpadded = AesLocker::remove_pkcs7_padding(&padded)
            .expect("Padding removal failed");
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_multiple_block_encryption() {
        let password = "test";
        // 创建超过一个AES块的数据（16字节）
        let data = b"This is a message longer than a single AES block";
        
        let encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");
        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");
        
        assert_eq!(decrypted, data);
    }

    #[tokio::test]
    async fn test_async_locker_id() {
        let locker = AesLocker::new();
        let id = locker.locker_id();
        assert_eq!(id, *b"AES\0");
    }

    #[test]
    fn test_various_password_lengths() {
        let data = b"Test data for various passwords";
        
        let passwords = vec![
            "a",                          // 最短
            "password",                   // 普通
            "very_long_password_with_many_characters_1234567890", // 长密码
        ];

        for password in passwords {
            let encrypted = AesLocker::encrypt_data(data, password)
                .expect(&format!("Encryption failed for password: {}", password));
            let decrypted = AesLocker::decrypt_data(&encrypted, password)
                .expect(&format!("Decryption failed for password: {}", password));
            assert_eq!(decrypted, data);
        }
    }

    #[test]
    fn test_special_characters_in_data() {
        let password = "password";
        let data = &[0u8, 1, 2, 3, 255, 254, 253];

        let encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");
        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_unicode_in_password() {
        let password = "密码🔐中文";  // 中文密码
        let data = b"Secret message";

        let encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");
        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_exact_multiple_of_block_size() {
        let password = "test_password";
        // 恰好是16字节的倍数（无填充需要）
        let data = b"0123456789ABCDEF0123456789ABCDEF"; // 32字节

        let encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");
        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_data_at_boundary_plus_one() {
        let password = "test_password";
        // 比块大小多1字节
        let data = b"0123456789ABCDEF0"; // 17字节

        let encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");
        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_truncated_data_fails() {
        let password = "password";
        let data = b"Test data";

        let encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");

        // 截断数据至只包含salt和部分iv
        let truncated = &encrypted[..SALT_LENGTH + 4];
        let result = AesLocker::decrypt_data(truncated, password);
        
        // 应该失败（因为数据太短）
        assert!(result.is_err());
    }

    #[test]
    fn test_repeated_encryptions_consistency() {
        let password = "test_password";
        let data = b"Consistency test data";

        // 多次加密同一数据，结果应该不同但都能正确解密
        let mut encrypted_results = Vec::new();
        for _ in 0..5 {
            let encrypted = AesLocker::encrypt_data(data, password)
                .expect("Encryption failed");
            encrypted_results.push(encrypted);
        }

        // 所有加密结果应该互不相同（因为随机盐和IV）
        for i in 0..encrypted_results.len() {
            for j in (i + 1)..encrypted_results.len() {
                assert_ne!(encrypted_results[i], encrypted_results[j]);
            }
        }

        // 但所有加密结果都应该能用相同密码正确解密
        for encrypted in encrypted_results {
            let decrypted = AesLocker::decrypt_data(&encrypted, password)
                .expect("Decryption failed");
            assert_eq!(decrypted, data);
        }
    }

    #[test]
    fn test_single_byte_data() {
        let password = "password";
        let data = &[42u8];

        let encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");
        let decrypted = AesLocker::decrypt_data(&encrypted, password)
            .expect("Decryption failed");
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_size_structure() {
        let password = "test";
        let data = b"Test data here";
        
        let encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");
        
        // 验证加密数据结构: salt (16) + iv (16) + encrypted_data (应该是16的倍数)
        assert!(encrypted.len() >= SALT_LENGTH + IV_LENGTH);
        
        let encrypted_data_len = encrypted.len() - SALT_LENGTH - IV_LENGTH;
        assert_eq!(encrypted_data_len % BLOCK_SIZE, 0, 
                   "Encrypted data should be multiple of block size");
    }

    #[test]
    fn test_wrong_salt_corruption() {
        let password = "password";
        let data = b"Test data";

        let mut encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");

        // 修改salt部分
        encrypted[0] ^= 0xFF;

        // 解密应该因为密钥错误而失败（填充校验不通过）
        let result = AesLocker::decrypt_data(&encrypted, password);
        if let Ok(decrypted) = result {
            assert_ne!(decrypted, data);
        }
    }

    #[test]
    fn test_iv_corruption() {
        let password = "password";
        let data = b"Test data";

        let mut encrypted = AesLocker::encrypt_data(data, password)
            .expect("Encryption failed");

        // 修改IV部分
        encrypted[SALT_LENGTH] ^= 0xFF;

        // 解密应该产生不同的数据
        let result = AesLocker::decrypt_data(&encrypted, password);
        if let Ok(decrypted) = result {
            assert_ne!(decrypted, data);
        }
    }
}
