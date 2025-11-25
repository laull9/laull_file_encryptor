use super::base::{
    Locker
};
use std::path::{PathBuf};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use ring::{aead, hkdf, rand};
use ring::rand::SecureRandom;
use std::convert::TryInto;


// 常量（可根据需要调整）
const PLAINTEXT_CHUNK_SIZE: usize = 64 * 1024; // 每块 64KiB 明文
const AEAD_TAG_LEN: usize = 16; // ChaCha20-Poly1305 tag 长度
const NONCE_PREFIX_LEN: usize = 4; // 我们用 4 字节随机前缀 + 8 字节计数器 -> 12 字节 nonce
const NONCE_LEN: usize = 12;
const HKDF_SALT: &[u8] = b"cha-cha-locker-salt"; // 派生盐（可固定或参数化）

// 需要你已有的 trait & helper 函数（write_trailer, remove_trailer, ...）在同一模块可见
// 假设 Locker trait 如你已给出（locker_id, lock_inner, unlock_inner 等）。

pub struct ChaChaLocker;

impl ChaChaLocker {
    pub fn new() -> Self {
        Self
    }

    /// 从 password 派生出一个 32 字节的 AEAD key（用于 CHACHA20_POLY1305）
    fn derive_key(password: &str) -> [u8; 32] {
        // 用 HKDF-SHA256 从密码派生 32 字节
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
        let prk = salt.extract(password.as_bytes());
        let okm = prk.expand(&[], hkdf::HKDF_SHA256).expect("hkdf expand");
        let mut key = [0u8; 32];
        okm.fill(&mut key).expect("hkdf fill");
        key
    }

    /// 构造 12 字节 nonce：prefix(4) + counter(u64 big-endian)
    fn nonce_from_prefix_counter(prefix: &[u8; NONCE_PREFIX_LEN], counter: u64) -> aead::Nonce {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
        nonce_bytes[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
        aead::Nonce::assume_unique_for_key(nonce_bytes)
    }
}

#[async_trait]
impl Locker for ChaChaLocker {
    fn locker_id(&self) -> [u8; 4] {
        *b"CC20"
    }

    async fn lock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        // 打开原始文件读取
        let mut src = File::open(&filepath).await?;
        let metadata = src.metadata().await?;
        let _orig_len = metadata.len();

        // 在同目录下创建临时文件
        let tmp_path = filepath.with_extension("enc_tmp");
        let mut dst = File::create(&tmp_path).await?;

        // 派生 key
        let key_bytes = Self::derive_key(&password);
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, "Invalid key"))?;
        let less_safe = aead::LessSafeKey::new(unbound);

        // 生成 4 字节随机 prefix（nonce 的前 4 字节）
        let rng = rand::SystemRandom::new();
        let mut prefix = [0u8; NONCE_PREFIX_LEN];
        rng.fill(&mut prefix).map_err(|_| tokio::io::Error::new(tokio::io::ErrorKind::Other, "RNG failure"))?;
        // 写出前缀（12 字节 nonce 的前 4 字节；后续解密会使用）
        // 我们只写 12 字节 nonce-prefix? 实际上我们只 need to write the 4-byte prefix; but to keep simplicity write 12? 
        // 这里写出全部 12 字节 initial nonce (prefix + counter=0) 方便读取；写出 prefix + counter(0) 即 12 字节
        let initial_nonce = ChaChaLocker::nonce_from_prefix_counter(&prefix, 0);
        dst.write_all(initial_nonce.as_ref()).await?;

        // 流式读取明文块并每块加密写入
        let mut buf = vec![0u8; PLAINTEXT_CHUNK_SIZE];
        let mut counter: u64 = 0;
        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut in_out = Vec::with_capacity(n + AEAD_TAG_LEN);
            in_out.extend_from_slice(&buf[..n]);
            // seal_in_place_append_tag 需要一个 aead::Nonce
            let nonce = ChaChaLocker::nonce_from_prefix_counter(&prefix, counter);
            // seal
            let aad = aead::Aad::empty();
            let res = less_safe.seal_in_place_separate_tag(nonce, aad, &mut in_out)
                .map_err(|_| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, "seal failed"))?;
            // append tag
            in_out.extend_from_slice(res.as_ref());
            // 写出密文+tag
            dst.write_all(&in_out).await?;
            counter = counter.wrapping_add(1);
        }

        // flush & sync
        dst.sync_all().await.ok();

        // 原子替换（先备份或直接重命名覆盖）
        // 一些平台上 rename 会覆盖，tokio::fs::rename 默认行为取决于平台
        fs::rename(&tmp_path, &filepath).await?;

        Ok(())
    }

    async fn unlock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        // 打开加密文件
        let mut src = File::open(&filepath).await?;

        // 读取并解析初始 12 字节 nonce（prefix + counter=0）；
        let mut nonce0 = [0u8; NONCE_LEN];
        src.read_exact(&mut nonce0).await?;
        let prefix: [u8; NONCE_PREFIX_LEN] = nonce0[..NONCE_PREFIX_LEN].try_into().unwrap();

        // 创建临时解密文件
        let tmp_path = filepath.with_extension("dec_tmp");
        let mut dst = File::create(&tmp_path).await?;

        // 派生 key
        let key_bytes = Self::derive_key(&password);
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, "Invalid key"))?;
        let less_safe = aead::LessSafeKey::new(unbound);

        // 现在从 src 的当前位置（已经读过 12 字节）开始，按块读取密文+tag 并解密
        let mut counter: u64 = 0;
        // 每次读取 ciphertext 块：最多 PLAINTEXT_CHUNK_SIZE + AEAD_TAG_LEN
        let mut read_buf = vec![0u8; PLAINTEXT_CHUNK_SIZE + AEAD_TAG_LEN];
        loop {
            // 尽量读取 full (plaintext_chunk + tag)，但最后一块可能更短
            let n = src.read(&mut read_buf).await?;
            if n == 0 {
                break;
            }
            // read_buf[..n] 是 ciphertext + tag
            let mut in_out = read_buf[..n].to_vec();
            let nonce = ChaChaLocker::nonce_from_prefix_counter(&prefix, counter);
            let aad = aead::Aad::empty();
            // open_in_place expects the tag at the end of buffer
            let plain = less_safe.open_in_place(nonce, aad, &mut in_out)
                .map_err(|_| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, "decryption failed"))?;
            // 将明文写入目标文件
            dst.write_all(plain).await?;
            counter = counter.wrapping_add(1);
        }

        dst.sync_all().await.ok();
        // 原子替换：用解密后的文件替换加密文件
        fs::rename(&tmp_path, &filepath).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::rand::TryRngCore;
    use tokio::fs::{File};
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    use tempfile::tempdir;
    use super::super::base::{
        read_trailer_if_exists,
        verify_trailer,
    };

    const PASSWORD: &str = "mypassword";

    /// 生成随机内容（可选大文件用）
    async fn write_random_file(path: &std::path::Path, size: usize) {
        use ::rand::{rngs::OsRng};
        let mut data = vec![0u8; size];
        let _ = OsRng.try_fill_bytes(&mut data);

        let mut f = File::create(path).await.unwrap();
        f.write_all(&data).await.unwrap();
    }

    async fn read_all(path: &std::path::Path) -> Vec<u8> {
        let mut f = File::open(path).await.unwrap();
        let mut data = Vec::new();
        f.read_to_end(&mut data).await.unwrap();
        data
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_small_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        // 写明文
        let content = b"Hello world, this is a ChaCha20 test!";
        {
            let mut f = File::create(&file_path).await.unwrap();
            f.write_all(content).await.unwrap();
        }

        let locker = ChaChaLocker::new();

        // 加密
        locker.lock(&file_path, PASSWORD.to_string())
            .await.unwrap();

        // 加密后文件肯定不一样
        let encrypted = read_all(&file_path).await;
        assert_ne!(encrypted, content);

        // 解密
        locker.unlock(&file_path, PASSWORD.to_string())
            .await.unwrap();

        // 内容应恢复
        let decrypted = read_all(&file_path).await;
        assert_eq!(decrypted, content);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_large_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("big.bin");

        // 写入 8MB 随机文件
        write_random_file(&file_path, 8 * 1024 * 1024).await;
        let original = read_all(&file_path).await;

        let locker = ChaChaLocker::new();

        // 加密
        locker.lock(&file_path, PASSWORD.to_string())
            .await.unwrap();

        let encrypted = read_all(&file_path).await;
        assert!(encrypted.len() > original.len());  // 加上 nonce 和 AEAD tag

        // 解密
        locker.unlock(&file_path, PASSWORD.to_string())
            .await.unwrap();

        let decrypted = read_all(&file_path).await;
        assert_eq!(decrypted, original); // 必须完全一致
    }

    #[tokio::test]
    async fn test_wrong_password_fails() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("wrong_pwd.txt");

        let content = b"Secret Data!!! 1234567890";
        {
            let mut f = File::create(&file_path).await.unwrap();
            f.write_all(content).await.unwrap();
        }

        let locker = ChaChaLocker::new();

        // 加密
        locker.lock(&file_path, PASSWORD.to_string())
            .await.unwrap();

        // 使用错误密码解密 —— 应失败
        let result = locker.unlock(&file_path, "wrong".to_string()).await;
        assert!(result.is_err(), "应该因密码错误解密失败");
    }

    #[tokio::test]
    async fn test_trailer_written_and_verified() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("tag_test.bin");

        let content = b"Trailer test content";
        {
            let mut f = File::create(&file_path).await.unwrap();
            f.write_all(content).await.unwrap();
        }

        let locker = ChaChaLocker::new();

        // 加密（内含写 trailer）
        locker.lock(&file_path, PASSWORD.to_string())
            .await.unwrap();

        // 读取 trailer
        let trailer = read_trailer_if_exists(&file_path)
            .await.unwrap();

        assert!(trailer.is_some(), "应找到 trailer");

        let (locker_id, tag) = trailer.unwrap();
        assert_eq!(&locker_id, b"CC20");
        assert_eq!(tag.len(), 32);

        // 验证 trailer
        assert!(
            verify_trailer(&file_path, *b"CC20", PASSWORD).await.unwrap(),
            "应验证通过 trailer"
        );
    }
}
