use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use std::sync::Arc;
use tokio::sync::Semaphore;
use async_trait::async_trait;

type HmacSha256 = Hmac<Sha256>;
const MAX_CONCURRENT: usize = 16;

const TRAITER_ID_LEN: usize = 4;
const TRAITER_TAG_LEN: usize = 32;
const TRAILER_FINISH_TAG: [u8; 8] = *b";;!FQ!;;";
const TRAILER_FINISH_TAG_LEN: usize = 8;
const TRAILER_LEN: usize = TRAITER_ID_LEN + TRAITER_TAG_LEN + TRAILER_FINISH_TAG_LEN;

const HEADER_LEN: usize = 1024;    // read first 1KB to compute tag

pub async fn scan_files_iterative<F>(root: &Path, mut callback: F) -> tokio::io::Result<()> 
where 
    F: FnMut(PathBuf),
{
    let mut directories = VecDeque::new();
    directories.push_back(root.to_path_buf());
    
    while let Some(current_dir) = directories.pop_front() {
        let mut entries = match fs::read_dir(&current_dir).await {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("无法读取目录 {}: {}", current_dir.display(), e);
                continue;
            }
        };
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            let metadata = match fs::metadata(&path).await {
                Ok(meta) => meta,
                Err(e) => {
                    eprintln!("无法获取文件元数据 {}: {}", path.display(), e);
                    continue;
                }
            };
            
            if metadata.is_file() {
                callback(path);
            } else if metadata.is_dir() {
                directories.push_back(path);
            }
        }
    }
    
    Ok(())
}

#[async_trait]
pub trait Locker: Send + Sync + 'static {
    // 每个 locker 返回自己的 ID（改为方法以支持 trait 对象）
    fn locker_id(&self) -> [u8; TRAITER_ID_LEN];
    async fn lock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()>;
    async fn unlock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()>;
    async fn is_locked(&self, filepath: PathBuf) 
        -> tokio::io::Result<bool>
    {
        Ok(read_trailer_if_exists(filepath).await?.is_some())
    }


    async fn lock(&self, filepath: PathBuf, password: String) 
        -> tokio::io::Result<()>
    {
        if self.is_locked(filepath.clone()).await? {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::AlreadyExists,
                "File is already locked",
            ));
        }
        self.lock_inner(filepath.clone(), password.clone()).await?;
        write_trailer(&filepath, self.locker_id(), &password).await
    }

    async fn unlock(&self, filepath: PathBuf, password: String) 
        -> tokio::io::Result<()>
    {
        if !verify_trailer(&filepath, self.locker_id(), &password).await? {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "Wrong password or file is not locked by this Locker",
            ));
        }
        remove_trailer(&filepath).await?;
        self.unlock_inner(filepath, password).await
    }
}

pub async fn compute_tag_with_len(
    file: &mut File,
    password: &str,
    content_len: u64,
) -> tokio::io::Result<[u8; TRAITER_TAG_LEN]>
{
    let read_len = HEADER_LEN.min(content_len as usize);
    let mut header = vec![0u8; read_len];

    // 必须 seek，否则会读到中间位置
    file.seek(std::io::SeekFrom::Start(0)).await?;

    if read_len > 0 {
        file.read_exact(&mut header).await?;
    }

    let mut pwd_hash = Sha256::new();
    pwd_hash.update(password.as_bytes());
    let pwd_key = pwd_hash.finalize();

    let mut mac = HmacSha256::new_from_slice(&pwd_key).unwrap();
    mac.update(&header);

    Ok(mac.finalize().into_bytes().into())
}

// 工具函数：计算 tag
// pub async fn compute_tag(file: &mut File, password: &str) -> tokio::io::Result<[u8; 32]> {
//     let meta = file.metadata().await?;
//     let file_len = meta.len();

//     compute_tag_with_len(file, password, file_len).await
// }


// 写尾标：locker_id + tag
pub async fn write_trailer<P: AsRef<Path>>(
    path: P, locker_id: [u8;TRAITER_ID_LEN], password: &str
) -> tokio::io::Result<()> {

    // 以可读写方式打开
    let mut file = File::options().read(true).write(true).open(&path).await?;
    let meta = file.metadata().await?;
    let file_len = meta.len();

    // 仅当文件确实已经包含尾标时才截断旧尾标
    // （复用你已有的 read_trailer_if_exists）
    let content_len = if file_len >= TRAILER_LEN as u64 {
        if let Ok(Some(_)) = read_trailer_if_exists(&path).await {
            // 文件尾确实有旧 trailer，移除它
            file.set_len(file_len - TRAILER_LEN as u64).await?;
            file_len - TRAILER_LEN as u64
        } else {
            // 无旧 trailer，保持原文件长度
            file_len
        }
    } else {
        file_len
    };

    // 重新计算 tag（在截断旧尾标后的内容上算）
    let mut file2 = File::options().read(true).open(&path).await?;
    let tag = compute_tag_with_len(&mut file2, password, content_len).await?;

    // 追加 tail（locker_id + tag + finish_tag）
    file.seek(std::io::SeekFrom::End(0)).await?;
    file.write_all(&locker_id).await?;
    file.write_all(&tag).await?;
    file.write_all(&TRAILER_FINISH_TAG).await?;
    Ok(())
}

pub async fn read_trailer_if_exists<P: AsRef<Path>>(
    path: P
) -> tokio::io::Result<Option<([u8; TRAITER_ID_LEN], [u8; TRAITER_TAG_LEN])>> {

    let mut file = File::options().read(true).open(&path).await?;
    let metadata = file.metadata().await?;
    let file_len = metadata.len();

    if file_len < TRAILER_LEN as u64 {
        return Ok(None);
    }

    let mut buf = vec![0u8; TRAILER_LEN];
    file.seek(std::io::SeekFrom::End(-(TRAILER_LEN as i64))).await?;
    file.read_exact(&mut buf).await?;

    let locker_id: [u8; TRAITER_ID_LEN] = buf[..TRAITER_ID_LEN].try_into().unwrap();
    let tag: [u8; 32] = buf[TRAITER_ID_LEN..(TRAITER_ID_LEN + TRAITER_TAG_LEN)].try_into().unwrap();
    let finish_tag: [u8; 8] = buf[(TRAITER_ID_LEN + TRAITER_TAG_LEN)..].try_into().unwrap();
    if finish_tag != TRAILER_FINISH_TAG {
        return Ok(None);
    }

    Ok(Some((locker_id, tag)))
}

// 验证尾标
pub async fn verify_trailer<P: AsRef<Path>>(
    path: P, expected_locker_id: [u8;4], password: &str
) -> tokio::io::Result<bool> {

    // 读取尾标
    let Some((stored_locker_id, stored_tag)) = read_trailer_if_exists(&path).await? else {
        return Ok(false);
    };

    // ID 不匹配直接 false
    if stored_locker_id != expected_locker_id {
        return Ok(false);
    }

    // 重新计算 tag
    let metadata = tokio::fs::metadata(&path).await?;
    let file_len = metadata.len();
    let content_len = file_len - TRAILER_LEN as u64;

    let mut file = File::options().read(true).open(&path).await?;
    let computed_tag = compute_tag_with_len(&mut file, password, content_len).await?;

    Ok(stored_tag == computed_tag)
}


// 删除尾标（解锁时）
pub async fn remove_trailer<P: AsRef<Path>>(path: P) -> tokio::io::Result<()> {
    let file = File::options().read(true).write(true).open(&path).await?;
    let metadata = file.metadata().await?;
    let new_len = metadata.len() - TRAILER_LEN as u64;
    file.set_len(new_len).await?;
    Ok(())
}

pub struct DirLockManager {
    semaphore: Arc<Semaphore>,
    dir_path: PathBuf,
    password: String,
    locker: Arc<dyn Locker>,
}

impl DirLockManager {
    pub fn new<P, L>(dir_path: P, password: String, locker: L) -> Self
    where
        P: AsRef<Path>,
        L: Locker + 'static
    {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            dir_path: dir_path.as_ref().to_path_buf(),
            password,
            locker: Arc::new(locker),
        }
    }

    pub async fn lock(&self) {
        if let Err(e) = scan_files_iterative(&self.dir_path, move |file_path| {
            let permit_fut = self.semaphore.clone().acquire_owned();
            let pwd2 = self.password.clone();
            let locker2 = self.locker.clone();

            tokio::spawn(async move {
                let _permit = permit_fut.await.expect("semaphore closed");

                if let Err(e) = locker2.lock(file_path, pwd2).await {
                    eprintln!("处理文件 时出错: {}", e);
                }
            });
        }).await {
            eprintln!("扫描目录时出错: {}", e);
        }
    }

    pub async fn unlock(&self) {
        if let Err(e) = scan_files_iterative(&self.dir_path, move |file_path| {
            let permit_fut = self.semaphore.clone().acquire_owned();
            let pwd2 = self.password.clone();
            let locker2 = self.locker.clone();

            tokio::spawn(async move {
                let _permit = permit_fut.await.expect("semaphore closed");

                if let Err(e) = locker2.unlock(file_path, pwd2).await {
                    eprintln!("处理文件 时出错: {}", e);
                }
            });
        }).await {
            eprintln!("扫描目录时出错: {}", e);
        }
    }
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
    async fn test_compute_tag_consistent() {
        let path = unique_path("compute_tag");
        let data = b"hello compute tag".to_vec();
        fs::write(&path, &data).await.unwrap();

        let mut f1 = File::options().read(true).open(&path).await.unwrap();
        let f1_len = f1.metadata().await.unwrap().len();
        let tag1 = compute_tag_with_len(
            &mut f1, "pw", f1_len)
            .await.unwrap();

        let mut f2 = File::options().read(true).open(&path).await.unwrap();
        let f2_len = f2.metadata().await.unwrap().len();
        let tag2 = compute_tag_with_len(
            &mut f2, "pw", f2_len)
            .await.unwrap();

        assert_eq!(tag1, tag2);

        fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn test_trailer_write_verify_remove() {
        let path = unique_path("trailer_flow");
        let data = b"some content for trailer test".to_vec();
        fs::write(&path, &data).await.unwrap();

        // write trailer with correct password
        write_trailer(&path, *b"TEST", "secret").await.unwrap();

        // verify with correct password
        let ok = verify_trailer(&path, *b"TEST", "secret").await.unwrap();
        assert!(ok, "verify_trailer should succeed with correct password");

        // wrong locker id -> false
        let ok2 = verify_trailer(&path, *b"WRNG", "secret").await.unwrap();
        assert!(!ok2, "verify_trailer with wrong locker id must be false");

        // wrong password -> false
        let ok3 = verify_trailer(&path, *b"TEST", "bad").await.unwrap();
        assert!(!ok3, "verify_trailer with wrong password must be false");

        // remove trailer
        remove_trailer(&path).await.unwrap();
        let ok4 = verify_trailer(&path, *b"TEST", "secret").await.unwrap();
        assert!(!ok4, "after remove_trailer verification must fail");

        fs::remove_file(&path).await.unwrap();
    }
}