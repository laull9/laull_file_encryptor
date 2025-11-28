use super::base::{
    Encryptor,
    read_trailer_if_exists,
    remove_trailer,
    verify_trailer,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use async_trait::async_trait;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use std::io::Error as IoError;
use std::io::ErrorKind;

const LOCKER_ID_PARALLEL: [u8; 4] = *b"AES1";
const LOCKER_ID_LEGACY: [u8; 4] = *b"AES\0";
const SALT_LENGTH: usize = 16;
const IV_LENGTH: usize = 16;
const KEY_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32;
const BLOCK_SIZE: usize = 16;
/// Legacy CBC streaming chunk size (64KiB keeps memory modest when decrypting compatibility data)
const CHUNK_SIZE: usize = 64 * 1024;
const PARALLEL_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const PARALLEL_IN_FLIGHT: usize = 4;

type Aes256Ctr = Ctr128BE<Aes256>;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AesEncryptor_slow;

impl AesEncryptor_slow {
    pub fn new() -> Self {
        AesEncryptor_slow
    }

    /// 从密码和盐派生加密密钥（PBKDF2-HMAC-SHA256）
    fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
        let mut key = [0u8; KEY_LENGTH];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, KEY_ITERATIONS, &mut key);
        key
    }

    /// 生成随机字节（跨平台、安全）
    fn fill_random(buf: &mut [u8]) -> Result<(), String> {
        getrandom::getrandom(buf).map_err(|e| format!("getrandom failed: {e}"))
    }

    /// PKCS#7 填充（用于 legacy CBC 加密的最后一块）
    fn add_pkcs7_padding_block(mut tail: Vec<u8>) -> Vec<u8> {
        let padding_len = BLOCK_SIZE - (tail.len() % BLOCK_SIZE);
        tail.extend(std::iter::repeat(padding_len as u8).take(padding_len));
        tail
    }

    /// 移除 PKCS#7 填充（legacy CBC 解密完成后处理最后一块）
    fn remove_pkcs7_padding(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() {
            return Err("Empty data".to_string());
        }
        let padding_len = data[data.len() - 1] as usize;
        if padding_len == 0 || padding_len > BLOCK_SIZE {
            return Err("Invalid padding length".to_string());
        }
        if data.len() < padding_len {
            return Err("Data shorter than padding".to_string());
        }
        for i in 0..padding_len {
            if data[data.len() - 1 - i] != padding_len as u8 {
                return Err("Invalid padding bytes".to_string());
            }
        }
        Ok(data[..data.len() - padding_len].to_vec())
    }

    fn blocks_for_len(len: usize) -> u128 {
        if len == 0 {
            0
        } else {
            ((len + BLOCK_SIZE - 1) / BLOCK_SIZE) as u128
        }
    }

    fn process_ctr_chunk(
        chunk: &mut [u8],
        key: &[u8; KEY_LENGTH],
        iv: &[u8; IV_LENGTH],
        start_block: u128,
    ) -> Result<(), IoError> {
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(iv),
        );
        let byte_offset = start_block
            .checked_mul(BLOCK_SIZE as u128)
            .ok_or_else(|| IoError::new(ErrorKind::Other, "Stream offset overflow"))?;
        if byte_offset > u64::MAX as u128 {
            return Err(IoError::new(ErrorKind::Other, "Stream offset too large"));
        }
        cipher.seek(byte_offset as u64);
        cipher.apply_keystream(chunk);
        Ok(())
    }

    async fn parallel_ctr_copy(
        reader: &mut File,
        writer: &mut File,
        key: [u8; KEY_LENGTH],
        iv: [u8; IV_LENGTH],
    ) -> Result<(), IoError> {
        let mut join_set: JoinSet<Result<(u64, Vec<u8>), IoError>> = JoinSet::new();
        let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut next_write_index: u64 = 0;
        let mut chunk_index: u64 = 0;
        let mut total_blocks: u128 = 0;
        let mut read_finished = false;
        let mut active_tasks = 0usize;

        while !read_finished || active_tasks > 0 {
            while !read_finished && active_tasks < PARALLEL_IN_FLIGHT {
                let mut buf = vec![0u8; PARALLEL_CHUNK_SIZE];
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    read_finished = true;
                    break;
                }
                buf.truncate(n);
                let start_block = total_blocks;
                total_blocks += Self::blocks_for_len(n);
                let chunk_id = chunk_index;
                chunk_index += 1;
                let key_copy = key;
                join_set.spawn(async move {
                    let mut chunk = buf;
                    AesEncryptor_slow::process_ctr_chunk(&mut chunk, &key_copy, &iv, start_block)?;
                    Ok::<_, IoError>((chunk_id, chunk))
                });
                active_tasks += 1;
            }

            if active_tasks == 0 {
                continue;
            }

            if let Some(res) = join_set.join_next().await {
                active_tasks -= 1;
                let (idx, chunk) = res
                    .map_err(|e| IoError::new(ErrorKind::Other, e))??;
                pending.insert(idx, chunk);
                while let Some(data) = pending.remove(&next_write_index) {
                    writer.write_all(&data).await?;
                    next_write_index += 1;
                }
            }
        }

        Ok(())
    }

    async fn encrypt_stream_to_file_parallel(
        &self,
        src_path: &PathBuf,
        dst_path: &PathBuf,
        password: &str,
    ) -> Result<(), IoError> {
        let mut salt = [0u8; SALT_LENGTH];
        let mut iv = [0u8; IV_LENGTH];
        Self::fill_random(&mut salt).map_err(|e| IoError::new(ErrorKind::Other, e))?;
        Self::fill_random(&mut iv).map_err(|e| IoError::new(ErrorKind::Other, e))?;

        let key = Self::derive_key(password, &salt);
        let mut reader = File::open(src_path).await?;
        let mut writer = File::create(dst_path).await?;
        writer.write_all(&salt).await?;
        writer.write_all(&iv).await?;
        Self::parallel_ctr_copy(&mut reader, &mut writer, key, iv).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn decrypt_stream_to_file_parallel(
        &self,
        src_path: &PathBuf,
        dst_path: &PathBuf,
        password: &str,
    ) -> Result<(), IoError> {
        let mut reader = File::open(src_path).await?;
        let mut header = vec![0u8; SALT_LENGTH + IV_LENGTH];
        reader.read_exact(&mut header).await?;
        let salt = &header[..SALT_LENGTH];
        let iv: [u8; IV_LENGTH] = header[SALT_LENGTH..].try_into().unwrap();
        let key = Self::derive_key(password, salt);
        let mut writer = File::create(dst_path).await?;
        Self::parallel_ctr_copy(&mut reader, &mut writer, key, iv).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Legacy: 按流对文件进行 AES-CBC 加密（流式，不把整个文件装入内存）
    async fn encrypt_stream_to_file_cbc(
        &self,
        src_path: &PathBuf,
        dst_path: &PathBuf,
        password: &str,
    ) -> Result<(), IoError> {
        let mut salt = [0u8; SALT_LENGTH];
        let mut iv = [0u8; IV_LENGTH];
        Self::fill_random(&mut salt).map_err(|e| IoError::new(ErrorKind::Other, e))?;
        Self::fill_random(&mut iv).map_err(|e| IoError::new(ErrorKind::Other, e))?;

        let key = Self::derive_key(password, &salt);
        let cipher = Aes256::new(GenericArray::from_slice(&key));

        let mut reader = File::open(src_path).await?;
        let mut writer = File::create(dst_path).await?;
        writer.write_all(&salt).await?;
        writer.write_all(&iv).await?;
        let mut prev_block = iv;
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut leftover: Vec<u8> = Vec::with_capacity(BLOCK_SIZE);

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            leftover.extend_from_slice(&buf[..n]);
            let process_len = leftover.len() - (leftover.len() % BLOCK_SIZE);
            if process_len == 0 {
                continue;
            }

            let mut offset = 0usize;
            while offset < process_len {
                let chunk = &mut leftover[offset..offset + BLOCK_SIZE];
                for i in 0..BLOCK_SIZE {
                    chunk[i] ^= prev_block[i];
                }
                let mut ga = GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut ga);
                writer.write_all(&ga).await?;
                prev_block.copy_from_slice(&ga);
                offset += BLOCK_SIZE;
            }

            let new_leftover = leftover.split_off(process_len);
            leftover = new_leftover;
        }

        let final_padded = Self::add_pkcs7_padding_block(leftover);
        let mut offset = 0usize;
        while offset < final_padded.len() {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&final_padded[offset..offset + BLOCK_SIZE]);
            for i in 0..BLOCK_SIZE {
                block[i] ^= prev_block[i];
            }
            let mut ga = GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut ga);
            writer.write_all(&ga).await?;
            prev_block.copy_from_slice(&ga);
            offset += BLOCK_SIZE;
        }

        writer.flush().await?;
        Ok(())
    }

    /// Legacy：按流解密 AES-CBC 文件
    async fn decrypt_stream_to_file_cbc(
        &self,
        src_path: &PathBuf,
        dst_path: &PathBuf,
        password: &str,
    ) -> Result<(), IoError> {
        let mut reader = File::open(src_path).await?;
        let mut header = vec![0u8; SALT_LENGTH + IV_LENGTH];
        reader.read_exact(&mut header).await?;
        let salt = &header[..SALT_LENGTH];
        let iv = &header[SALT_LENGTH..SALT_LENGTH + IV_LENGTH];
        let key = Self::derive_key(password, salt);
        let cipher = Aes256::new(GenericArray::from_slice(&key));
        let mut writer = File::create(dst_path).await?;
        let mut prev_cipher_block = iv.to_vec();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut tail: Vec<u8> = Vec::with_capacity(BLOCK_SIZE);

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut data = Vec::with_capacity(tail.len() + n);
            data.extend_from_slice(&tail);
            data.extend_from_slice(&buf[..n]);

            if data.len() <= BLOCK_SIZE {
                tail = data;
                continue;
            }

            let process_len = data.len() - BLOCK_SIZE;
            let (to_process, new_tail) = data.split_at(process_len);
            tail = new_tail.to_vec();

            let mut offset = 0usize;
            while offset < to_process.len() {
                let enc_block = &to_process[offset..offset + BLOCK_SIZE];
                let mut ga = GenericArray::clone_from_slice(enc_block);
                cipher.decrypt_block(&mut ga);
                let mut plain_block = [0u8; BLOCK_SIZE];
                for i in 0..BLOCK_SIZE {
                    plain_block[i] = ga[i] ^ prev_cipher_block[i];
                }
                writer.write_all(&plain_block).await?;
                prev_cipher_block.copy_from_slice(enc_block);
                offset += BLOCK_SIZE;
            }
        }

        if tail.is_empty() {
            return Err(IoError::new(ErrorKind::InvalidData, "No ciphertext blocks found"));
        }
        if tail.len() % BLOCK_SIZE != 0 {
            return Err(IoError::new(ErrorKind::InvalidData, "Ciphertext not block-aligned"));
        }

        let tail_block_count = tail.len() / BLOCK_SIZE;
        if tail_block_count == 1 {
            let enc_block = &tail[0..BLOCK_SIZE];
            let mut ga = GenericArray::clone_from_slice(enc_block);
            cipher.decrypt_block(&mut ga);
            let mut plain_block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                plain_block[i] = ga[i] ^ prev_cipher_block[i];
            }
            let unpadded = Self::remove_pkcs7_padding(&plain_block)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
            writer.write_all(&unpadded).await?;
        } else {
            for i in 0..(tail_block_count - 1) {
                let start = i * BLOCK_SIZE;
                let enc_block = &tail[start..start + BLOCK_SIZE];
                let mut ga = GenericArray::clone_from_slice(enc_block);
                cipher.decrypt_block(&mut ga);
                let mut plain_block = [0u8; BLOCK_SIZE];
                for j in 0..BLOCK_SIZE {
                    plain_block[j] = ga[j] ^ prev_cipher_block[j];
                }
                writer.write_all(&plain_block).await?;
                prev_cipher_block.copy_from_slice(enc_block);
            }
            let last_start = (tail_block_count - 1) * BLOCK_SIZE;
            let enc_block = &tail[last_start..last_start + BLOCK_SIZE];
            let mut ga = GenericArray::clone_from_slice(enc_block);
            cipher.decrypt_block(&mut ga);
            let mut plain_block = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                plain_block[j] = ga[j] ^ prev_cipher_block[j];
            }
            let unpadded = Self::remove_pkcs7_padding(&plain_block)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
            writer.write_all(&unpadded).await?;
        }

        writer.flush().await?;
        Ok(())
    }

    async fn unlock_legacy(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        let mut tmp = filepath.clone();
        tmp.set_extension("aes_tmp");
        self.decrypt_stream_to_file_cbc(&filepath, &tmp, &password).await?;
        fs::rename(&tmp, &filepath).await?;
        Ok(())
    }
}

impl Default for AesEncryptor_slow {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Encryptor for AesEncryptor_slow {
    fn encryptor_id(&self) -> [u8; 4] {
        LOCKER_ID_PARALLEL
    }

    async fn lock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        let mut tmp = filepath.clone();
        tmp.set_extension("aes_tmp");
        self.encrypt_stream_to_file_parallel(&filepath, &tmp, &password)
            .await
            .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::Other, format!("{e}")))?;
        fs::rename(&tmp, &filepath).await?;
        Ok(())
    }

    async fn unlock(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        let trailer = read_trailer_if_exists(&filepath).await?;
        let Some((encryptor_id, _)) = trailer else {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "File is not locked",
            ));
        };

        if encryptor_id == LOCKER_ID_PARALLEL {
            if !verify_trailer(&filepath, LOCKER_ID_PARALLEL, &password).await? {
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::InvalidData,
                    "Wrong password or mismatched encryptor",
                ));
            }
            remove_trailer(&filepath).await?;
            self.unlock_inner(filepath, password).await
        } else if encryptor_id == LOCKER_ID_LEGACY {
            if !verify_trailer(&filepath, LOCKER_ID_LEGACY, &password).await? {
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::InvalidData,
                    "Wrong password or mismatched legacy encryptor",
                ));
            }
            remove_trailer(&filepath).await?;
            self.unlock_legacy(filepath, password).await
        } else {
            Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "Unknown AES encryptor identifier",
            ))
        }
    }

    async fn unlock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        let mut tmp = filepath.clone();
        tmp.set_extension("aes_tmp");
        self.decrypt_stream_to_file_parallel(&filepath, &tmp, &password)
            .await
            .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::Other, format!("{e}")))?;
        fs::rename(&tmp, &filepath).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;
    use tokio::time::Instant;
    use crate::file_encryptor::base::write_trailer;

    fn unique_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("rust_test_{}_{}", name, nanos));
        p
    }

    #[tokio::test]
    async fn test_lock_unlock_file_basic() {
        let encryptor = AesEncryptor_slow::new();
        let password = "test_password_123";

        let temp_file = unique_path("aes_test_basic");
        let original_content = b"Hello, this is a test file content!";
        fs::write(&temp_file, original_content).await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock file");

        let encrypted_content = fs::read(&temp_file).await.unwrap();
        assert_ne!(&encrypted_content, original_content);

        encryptor
            .unlock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to unlock file");

        let decrypted_content = fs::read(&temp_file).await.unwrap();
        assert_eq!(decrypted_content, original_content);

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_unlock_empty_file() {
        let encryptor = AesEncryptor_slow::new();
        let password = "empty_file_pwd";

        let temp_file = unique_path("aes_test_empty");
        fs::write(&temp_file, b"").await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock empty file");

        encryptor
            .unlock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to unlock empty file");

        let result = fs::read(&temp_file).await.unwrap();
        assert_eq!(result, b"");

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_unlock_large_file() {
        let encryptor = AesEncryptor_slow::new();
        let password = "large_file_pwd";

        let temp_file = unique_path("aes_test_large");
        let large_content: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        fs::write(&temp_file, &large_content).await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock large file");

        encryptor
            .unlock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to unlock large file");

        let decrypted = fs::read(&temp_file).await.unwrap();
        assert_eq!(decrypted, large_content);

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_file_wrong_password_unlock_fails() {
        let encryptor = AesEncryptor_slow::new();
        let password = "correct_pwd";
        let wrong_password = "wrong_pwd";

        let temp_file = unique_path("aes_test_wrongpwd");
        let original_content = b"Secret content that should not be readable with wrong password";
        fs::write(&temp_file, original_content).await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock file");

        let result = encryptor
            .unlock_inner(temp_file.clone(), wrong_password.to_string())
            .await;

        match result {
            Err(_) => {}
            Ok(_) => {
                let corrupted_content = fs::read(&temp_file).await.unwrap();
                assert_ne!(corrupted_content, original_content);
            }
        }

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_unlock_binary_file() {
        let encryptor = AesEncryptor_slow::new();
        let password = "binary_file_pwd";

        let temp_file = unique_path("aes_test_binary");
        let binary_content: Vec<u8> = (0..=255).cycle().take(10000).collect();
        fs::write(&temp_file, &binary_content).await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock binary file");

        encryptor
            .unlock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to unlock binary file");

        let decrypted = fs::read(&temp_file).await.unwrap();
        assert_eq!(decrypted, binary_content);

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_unlock_file_multiple_times() {
        let encryptor = AesEncryptor_slow::new();
        let password = "repeat_pwd";

        let temp_file = unique_path("aes_test_repeat");
        let original_content = b"Content for multiple lock/unlock cycles";

        for i in 0..3 {
            fs::write(&temp_file, original_content).await.unwrap();

            encryptor
                .lock_inner(temp_file.clone(), password.to_string())
                .await
                .expect(&format!("Failed to lock file in cycle {i}"));

            encryptor
                .unlock_inner(temp_file.clone(), password.to_string())
                .await
                .expect(&format!("Failed to unlock file in cycle {i}"));

            let decrypted = fs::read(&temp_file).await.unwrap();
            assert_eq!(decrypted, original_content, "Cycle {i}: content mismatch");
        }

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_file_with_unicode_password() {
        let encryptor = AesEncryptor_slow::new();
        let password = "密码🔐中文テスト";

        let temp_file = unique_path("aes_test_unicode");
        let content = "Unicode password test: 你好世界";
        fs::write(&temp_file, content).await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock file with unicode password");

        encryptor
            .unlock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to unlock file with unicode password");

        let decrypted = fs::read(&temp_file).await.unwrap();
        assert_eq!(decrypted, content.as_bytes());

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_file_content_structure() {
        let encryptor = AesEncryptor_slow::new();
        let password = "structure_test";

        let temp_file = unique_path("aes_test_structure");
        let content = b"Test content for structure verification";
        fs::write(&temp_file, content).await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock file");

        let encrypted = fs::read(&temp_file).await.unwrap();
        let min_size = SALT_LENGTH + IV_LENGTH;
        assert!(
            encrypted.len() >= min_size,
            "Encrypted file size {} is less than minimum {}",
            encrypted.len(),
            min_size
        );

        encryptor
            .unlock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to unlock file");

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_file_with_special_characters() {
        let encryptor = AesEncryptor_slow::new();
        let password = "special!@#$%^&*()";

        let temp_file = unique_path("aes_test_special");
        let content = "Content with special chars: !@#$%^&*()[]{}|;:<>?,./";
        fs::write(&temp_file, content).await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock file");

        encryptor
            .unlock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to unlock file");

        let decrypted = fs::read(&temp_file).await.unwrap();
        assert_eq!(decrypted, content.as_bytes());

        fs::remove_file(&temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_lock_file_preserves_all_bytes() {
        let encryptor = AesEncryptor_slow::new();
        let password = "all_bytes_pwd";

        let temp_file = unique_path("aes_test_allbytes");
        let all_bytes: Vec<u8> = (0..=255).collect();
        fs::write(&temp_file, &all_bytes).await.unwrap();

        encryptor
            .lock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to lock file");

        encryptor
            .unlock_inner(temp_file.clone(), password.to_string())
            .await
            .expect("Failed to unlock file");

        let decrypted = fs::read(&temp_file).await.unwrap();
        assert_eq!(decrypted, all_bytes);

        fs::remove_file(&temp_file).await.unwrap();
    }

    async fn generate_large_file(path: &PathBuf, size_bytes: u64) -> tokio::io::Result<()> {
        let mut file = File::create(path).await?;
        const BLOCK: usize = 8 * 1024 * 1024;
        let buf = vec![0u8; BLOCK];
        let mut written = 0u64;

        while written < size_bytes {
            let to_write = std::cmp::min(BLOCK as u64, size_bytes - written) as usize;
            file.write_all(&buf[..to_write]).await?;
            written += to_write as u64;
        }

        file.flush().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_large_2g() {
        let encryptor = AesEncryptor_slow::new();
        let password = "test_password_123";

        let src = PathBuf::from("test_large.bin");
        let size: u64 = 2 * 1024 * 1024 * 1024;

        println!("Generating 2GB test file...");
        generate_large_file(&src, size).await.unwrap();
        assert_eq!(fs::metadata(&src).await.unwrap().len(), size);

        let start = Instant::now();
        encryptor.lock_inner(src.clone(), password.to_string()).await.unwrap();
        let enc_time = start.elapsed().as_secs_f64();
        let encrypted_size = fs::metadata(&src).await.unwrap().len();
        println!(
            "Encrypted 2GB -> {} bytes in {:.3}s, speed = {:.2} MB/s",
            encrypted_size,
            enc_time,
            (size as f64 / 1024.0 / 1024.0) / enc_time
        );

        let start = Instant::now();
        encryptor.unlock_inner(src.clone(), password.to_string()).await.unwrap();
        let dec_time = start.elapsed().as_secs_f64();
        println!(
            "Decrypted 2GB in {:.3}s, speed = {:.2} MB/s",
            dec_time,
            (size as f64 / 1024.0 / 1024.0) / dec_time
        );

        assert_eq!(fs::metadata(&src).await.unwrap().len(), size);
        fs::remove_file(&src).await.unwrap();
    }

    #[tokio::test]
    async fn test_unlocks_legacy_files() {
        let encryptor = AesEncryptor_slow::new();
        let password = "legacy_pwd";
        let temp_file = unique_path("aes_test_legacy");
        let original_content = b"Legacy CBC compatibility";
        fs::write(&temp_file, original_content).await.unwrap();

        let mut tmp = temp_file.clone();
        tmp.set_extension("aes_tmp");
        encryptor
            .encrypt_stream_to_file_cbc(&temp_file, &tmp, password)
            .await
            .unwrap();
        fs::rename(&tmp, &temp_file).await.unwrap();
        write_trailer(&temp_file, LOCKER_ID_LEGACY, password)
            .await
            .unwrap();

        encryptor
            .unlock(temp_file.clone(), password.to_string())
            .await
            .expect("unlock should support legacy files");

        let decrypted = fs::read(&temp_file).await.unwrap();
        assert_eq!(decrypted, original_content);
        fs::remove_file(&temp_file).await.unwrap();
    }
}
