use super::base::Locker;

use async_trait::async_trait;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{Error as IoError, ErrorKind};
use std::num::NonZeroU32;
use std::path::PathBuf;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type IoResult<T> = tokio::io::Result<T>;

const LOCKER_ID: [u8; 4] = *b"RLK2";
const HEADER_MAGIC: [u8; 4] = *b"RLK2";
const HEADER_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 4;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const DEFAULT_CHUNK_SIZE: usize = 512 * 1024; // 512KiB keeps memory modest, throughput high
const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024; // upper guardrail for corrupted headers
const PBKDF2_ITERATIONS: u32 = 200_000;

pub struct AesLocker;

impl AesLocker {
    pub fn new() -> Self {
        Self
    }

    fn rng_fill(buf: &mut [u8]) -> IoResult<()> {
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| IoError::new(ErrorKind::Other, "secure RNG failure"))
    }

    fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> IoResult<LessSafeKey> {
        let mut key = [0u8; KEY_LEN];
        let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt,
            password.as_bytes(),
            &mut key,
        );
        let unbound = UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| Self::invalid_data("failed to initialize AES-256 key"))?;
        Ok(LessSafeKey::new(unbound))
    }

    fn nonce_from(prefix: &[u8; NONCE_PREFIX_LEN], counter: u64) -> IoResult<Nonce> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
        nonce_bytes[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
        Ok(Nonce::assume_unique_for_key(nonce_bytes))
    }

    async fn write_header(writer: &mut File, header: &FileHeader) -> IoResult<()> {
        writer.write_all(&HEADER_MAGIC).await?;
        writer.write_all(&[HEADER_VERSION]).await?;
        writer.write_all(&header.salt).await?;
        writer.write_all(&header.nonce_prefix).await?;
        writer
            .write_all(&header.chunk_size.to_le_bytes())
            .await?
            ;
        Ok(())
    }

    async fn read_header(reader: &mut File) -> IoResult<FileHeader> {
        let mut magic = [0u8; HEADER_MAGIC.len()];
        reader.read_exact(&mut magic).await?;
        if magic != HEADER_MAGIC {
            return Err(Self::invalid_data("missing AES-CTR header"));
        }

        let mut version = [0u8; 1];
        reader.read_exact(&mut version).await?;
        if version[0] != HEADER_VERSION {
            return Err(Self::invalid_data("unsupported AES-CTR header version"));
        }

        let mut salt = [0u8; SALT_LEN];
        reader.read_exact(&mut salt).await?;
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        reader.read_exact(&mut nonce_prefix).await?;
        let mut chunk_bytes = [0u8; 4];
        reader.read_exact(&mut chunk_bytes).await?;
        let chunk_size = u32::from_le_bytes(chunk_bytes);

        FileHeader::new(salt, nonce_prefix, chunk_size)
    }

    async fn encrypt_stream(
        reader: &mut File,
        writer: &mut File,
        key: &LessSafeKey,
        header: &FileHeader,
    ) -> IoResult<()> {
        let mut chunk_buf = vec![0u8; header.chunk_capacity()];
        let mut counter = 0u64;

        loop {
            let bytes_read = reader.read(&mut chunk_buf).await?;
            if bytes_read == 0 {
                break;
            }

            if counter == u64::MAX {
                return Err(IoError::new(ErrorKind::Other, "nonce counter overflow"));
            }

            let mut working = chunk_buf[..bytes_read].to_vec();
            let nonce = Self::nonce_from(&header.nonce_prefix, counter)?;
            counter += 1;

            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::empty(), &mut working)
                .map_err(|_| Self::invalid_data("AES-CTR streaming seal failed"))?;
            working.extend_from_slice(tag.as_ref());

            writer
                .write_all(&(bytes_read as u32).to_le_bytes())
                .await?;
            writer.write_all(&working).await?;
        }

        Ok(())
    }

    async fn decrypt_stream(
        reader: &mut File,
        writer: &mut File,
        key: &LessSafeKey,
        header: &FileHeader,
    ) -> IoResult<()> {
        let mut counter = 0u64;

        loop {
            let chunk_len = match Self::read_chunk_len(reader).await? {
                Some(len) => len as usize,
                None => break,
            };

            if chunk_len > header.chunk_capacity() {
                return Err(Self::invalid_data("cipher chunk length out of bounds"));
            }

            let total_len = chunk_len
                .checked_add(TAG_LEN)
                .ok_or_else(|| Self::invalid_data("cipher chunk length overflow"))?;
            let mut buffer = vec![0u8; total_len];
            reader.read_exact(&mut buffer).await?;

            if counter == u64::MAX {
                return Err(IoError::new(ErrorKind::Other, "nonce counter overflow"));
            }

            let nonce = Self::nonce_from(&header.nonce_prefix, counter)?;
            counter += 1;

            let plaintext = key
                .open_in_place(nonce, Aad::empty(), &mut buffer)
                .map_err(|_| Self::invalid_data("ciphertext authentication failed"))?;
            if plaintext.len() != chunk_len {
                return Err(Self::invalid_data("plaintext length mismatch"));
            }
            writer.write_all(plaintext).await?;
        }

        Ok(())
    }

    async fn read_chunk_len(reader: &mut File) -> IoResult<Option<u32>> {
        let mut buf = [0u8; 4];
        let mut read = 0usize;
        while read < buf.len() {
            let n = reader.read(&mut buf[read..]).await?;
            if n == 0 {
                if read == 0 {
                    return Ok(None);
                }
                return Err(Self::invalid_data("truncated chunk header"));
            }
            read += n;
        }
        Ok(Some(u32::from_le_bytes(buf)))
    }

    fn invalid_data(msg: &str) -> IoError {
        IoError::new(ErrorKind::InvalidData, msg)
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
        LOCKER_ID
    }

    async fn lock_inner(&self, filepath: PathBuf, password: String) -> IoResult<()> {
        let header = FileHeader::random(DEFAULT_CHUNK_SIZE as u32)?;
        let key = Self::derive_key(&password, &header.salt)?;
        let tmp_path = filepath.with_extension("aes2_tmp");

        let mut reader = File::open(&filepath).await?;
        let mut writer = File::create(&tmp_path).await?;
        Self::write_header(&mut writer, &header).await?;
        Self::encrypt_stream(&mut reader, &mut writer, &key, &header).await?;
        writer.flush().await?;
        writer.sync_all().await.ok();

        drop(reader);
        drop(writer);

        fs::rename(&tmp_path, &filepath).await?;
        Ok(())
    }

    async fn unlock_inner(&self, filepath: PathBuf, password: String) -> IoResult<()> {
        let tmp_path = filepath.with_extension("aes2_tmp");
        let mut reader = File::open(&filepath).await?;
        let header = Self::read_header(&mut reader).await?;
        let key = Self::derive_key(&password, &header.salt)?;
        let mut writer = File::create(&tmp_path).await?;
        Self::decrypt_stream(&mut reader, &mut writer, &key, &header).await?;
        writer.flush().await?;
        writer.sync_all().await.ok();

        drop(reader);
        drop(writer);

        fs::rename(&tmp_path, &filepath).await?;
        Ok(())
    }
}

#[derive(Clone)]
struct FileHeader {
    salt: [u8; SALT_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size: u32,
}

impl FileHeader {
    fn new(salt: [u8; SALT_LEN], nonce_prefix: [u8; NONCE_PREFIX_LEN], chunk_size: u32) -> IoResult<Self> {
        let chunk = chunk_size as usize;
        if chunk == 0 || chunk > MAX_CHUNK_SIZE {
            return Err(IoError::new(ErrorKind::InvalidData, "chunk size out of range"));
        }
        Ok(Self {
            salt,
            nonce_prefix,
            chunk_size,
        })
    }

    fn random(chunk_size: u32) -> IoResult<Self> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        AesLocker::rng_fill(&mut salt)?;
        AesLocker::rng_fill(&mut nonce_prefix)?;
        Self::new(salt, nonce_prefix, chunk_size)
    }

    fn chunk_capacity(&self) -> usize {
        self.chunk_size as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;

    fn unique_path(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("ring_aes_ctr_{tag}_{nanos}"));
        path
    }

    #[tokio::test]
    async fn round_trip_small_file() {
        let locker = AesLocker::new();
        let password = "let_me_in";
        let path = unique_path("small");
        fs::write(&path, b"hello world").await.unwrap();

        locker
            .lock_inner(path.clone(), password.to_string())
            .await
            .unwrap();
        locker
            .unlock_inner(path.clone(), password.to_string())
            .await
            .unwrap();

        let data = fs::read(&path).await.unwrap();
        assert_eq!(data, b"hello world");
        fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn round_trip_large_file() {
        let locker = AesLocker::new();
        let password = "super_secure";
        let path = unique_path("large");
        let payload: Vec<u8> = (0..(2 * 1024 * 1024)).map(|n| (n % 251) as u8).collect();
        fs::write(&path, &payload).await.unwrap();

        locker
            .lock_inner(path.clone(), password.to_string())
            .await
            .unwrap();
        locker
            .unlock_inner(path.clone(), password.to_string())
            .await
            .unwrap();

        let data = fs::read(&path).await.unwrap();
        assert_eq!(data, payload);
        fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn wrong_password_fails() {
        let locker = AesLocker::new();
        let path = unique_path("wrong_pwd");
        fs::write(&path, b"classified").await.unwrap();

        locker
            .lock_inner(path.clone(), "correct".to_string())
            .await
            .unwrap();

        let result = locker
            .unlock_inner(path.clone(), "incorrect".to_string())
            .await;
        assert!(result.is_err());

        fs::remove_file(&path).await.unwrap();
    }
}
