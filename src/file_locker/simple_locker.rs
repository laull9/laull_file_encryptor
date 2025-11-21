use super::base::{
    Locker
};
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;

const REPLACE_FILE_LEN: u64 = 1024;

pub struct SimpleLocker;

impl SimpleLocker {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Locker for SimpleLocker {
    fn locker_id(&self) -> [u8;4] { *b"SIMP" }

    async fn lock_inner(&self, filepath: PathBuf, _password: String) -> tokio::io::Result<()> {
        file_lock_unlock_async(&filepath).await
    }

    async fn unlock_inner(&self, filepath: PathBuf, _password: String) -> tokio::io::Result<()> {
        file_lock_unlock_async(&filepath).await
    }
}


pub async fn file_lock_unlock_async<P: AsRef<Path>>(
    path: P
) -> tokio::io::Result<()> 
{
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    let mut file = tokio::fs::File::options()
        .read(true)
        .write(true)
        .open(&path)
        .await?;

    let metadata = file.metadata().await?;
    let file_size = metadata.len();

    let max_len = std::cmp::min(REPLACE_FILE_LEN, file_size) as usize;

    // 只读取目标区域
    let mut buffer = vec![0u8; max_len];
    file.seek(tokio::io::SeekFrom::Start(0)).await?;
    file.read_exact(&mut buffer).await?;

    // 区域加密/解密算法
    buffer.reverse();
    for b in buffer.iter_mut() {
        *b = u8::MAX - *b;
    }

    // 写回原区域
    file.seek(tokio::io::SeekFrom::Start(0)).await?;
    file.write_all(&buffer).await?;

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;

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
    async fn test_simple_locker_lock_unlock() {
        let path = unique_path("simple_locker");
        let original = b"the quick brown fox jumps".to_vec();
        fs::write(&path, &original).await.unwrap();

        let locker = SimpleLocker;
        let pwd = "s3cr3t".to_string();

        // lock
        locker.lock(path.clone(), pwd.clone()).await.unwrap();

        // should be locked
        let locked = locker.is_locked(path.clone()).await.unwrap();
        assert!(locked, "file should report locked after lock()");

        // unlocking with wrong password should error
        let wrong = locker.unlock(path.clone(), "bad".to_string()).await;
        assert!(wrong.is_err(), "unlock with wrong password should fail");

        // unlock with correct password 这里报错
        locker.unlock(path.clone(), pwd.clone()).await.unwrap();

        // file content restored
        let data = fs::read(&path).await.unwrap();
        assert_eq!(data, original, "content should match original after unlock");

        // not locked anymore
        let locked2 = locker.is_locked(path.clone()).await.unwrap();
        assert!(!locked2, "file should not be locked after unlock");

        fs::remove_file(&path).await.unwrap();
    }
}