use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use tokio::task::JoinSet;
use std::sync::{Arc, Mutex};
use tokio::sync::{Semaphore};
use async_trait::async_trait;

type HmacSha256 = Hmac<Sha256>;
const MAX_CONCURRENT: usize = 16;

const TRAITER_ID_LEN: usize = 4;
const TRAITER_TAG_LEN: usize = 32;
const TRAILER_FINISH_TAG: [u8; 8] = *b";;!FQ!;;";
const TRAILER_FINISH_TAG_LEN: usize = 8;
const TRAILER_LEN: usize = TRAITER_ID_LEN + TRAITER_TAG_LEN + TRAILER_FINISH_TAG_LEN;

const HEADER_LEN: usize = 1024;    // read first 1KB to compute tag

pub async fn scan_files_iterative<F>(paths: &Vec<String>, mut callback: F) -> tokio::io::Result<()>
where 
    F: FnMut(PathBuf),
{
    let mut directories = VecDeque::new();
    
    // 遍历每个传入的路径
    for path_str in paths {
        let path = Path::new(&path_str).to_path_buf();
        
        // 如果路径是文件夹，添加到目录队列中
        if path.is_dir() {
            directories.push_back(path);
        } else if path.is_file() {
            // 如果路径是文件，直接调用回调函数
            callback(path);
        } else {
            eprintln!("路径 {} 不存在或无法访问", path.display());
        }
    }

    // 处理所有目录
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

    // 打开可读写的同一个文件句柄（后续不再 reopen）
    let path_ref = path.as_ref();
    let mut file = File::options().read(true).write(true).open(path_ref).await?;
    let mut meta = file.metadata().await?;
    let mut file_len = meta.len();

    // 如果文件尾确实包含旧 trailer，就截断旧 trailer（用当前句柄）
    if file_len >= TRAILER_LEN as u64 {
        // 读取末尾判断是否为旧 trailer（直接用 file）
        let mut tail = vec![0u8; TRAILER_LEN];
        file.seek(std::io::SeekFrom::End(-(TRAILER_LEN as i64))).await?;
        if let Ok(_) = file.read_exact(&mut tail).await {
            let finish_tag = &tail[(TRAITER_ID_LEN + TRAITER_TAG_LEN)..];
            if finish_tag == TRAILER_FINISH_TAG {
                // 截断旧尾标：注意 set_len 会改变文件长度
                file.set_len(file_len - TRAILER_LEN as u64).await?;
                file_len = file_len - TRAILER_LEN as u64;
            } else {
                // 如果不是旧尾标，不做截断；恢复到文件末尾准备追加
                file.seek(std::io::SeekFrom::End(0)).await?;
            }
        } else {
            // 如果读取失败，回到文件末尾
            file.seek(std::io::SeekFrom::End(0)).await?;
        }
    }

    // 再次获取实际内容长度（以防 set_len 改变）
    meta = file.metadata().await?;
    let content_len = meta.len();

    // 确保内容已刷新到磁盘（尽量减少缓冲引起的不一致）
    file.sync_all().await.ok();

    // 计算 tag（在同一个 file handle 上）
    let tag = compute_tag_with_len(&mut file, password, content_len).await?;

    // 追加尾标（locker_id + tag + finish_tag）
    file.seek(std::io::SeekFrom::End(0)).await?;
    file.write_all(&locker_id).await?;
    file.write_all(&tag).await?;
    file.write_all(&TRAILER_FINISH_TAG).await?;

    // 强制 flush
    file.sync_all().await?;

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

    let path_ref = path.as_ref();
    let mut file = File::options().read(true).open(path_ref).await?;
    let metadata = file.metadata().await?;
    let file_len = metadata.len();

    if file_len < TRAILER_LEN as u64 {
        return Ok(false);
    }

    // 读取尾部
    file.seek(std::io::SeekFrom::End(-(TRAILER_LEN as i64))).await?;
    let mut buf = vec![0u8; TRAILER_LEN];
    file.read_exact(&mut buf).await?;

    let stored_locker_id: [u8; TRAITER_ID_LEN] = buf[..TRAITER_ID_LEN].try_into().unwrap();
    if stored_locker_id != expected_locker_id {
        return Ok(false);
    }
    let stored_tag: [u8; TRAITER_TAG_LEN] = buf[TRAITER_ID_LEN..TRAITER_ID_LEN + TRAITER_TAG_LEN].try_into().unwrap();
    let finish_tag: [u8; TRAILER_FINISH_TAG_LEN] = buf[(TRAITER_ID_LEN + TRAITER_TAG_LEN)..].try_into().unwrap();
    if finish_tag != TRAILER_FINISH_TAG {
        return Ok(false);
    }

    // content_len = file_len - TRAILER_LEN
    let content_len = file_len - TRAILER_LEN as u64;

    // 计算 tag：在同一个 file 上从头读取 header
    let computed = compute_tag_with_len(&mut file, password, content_len).await?;

    Ok(stored_tag == computed)
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
    paths: Vec<String>,
    password: String,
    locker: Arc<dyn Locker>,
    joinset: Arc<Mutex<JoinSet<()>>>,
    progress_total: Arc<Mutex<u64>>,
    progress_done: Arc<Mutex<u64>>,
    progress_err: Arc<Mutex<u64>>,
}

impl DirLockManager {
    pub fn new<L>(dir_path: Vec<String>, password: String, locker: L) -> Self
    where
        L: Locker + 'static
    {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            paths: dir_path,
            password,
            locker: Arc::new(locker),
            joinset: Arc::new(Mutex::new(JoinSet::new())),
            progress_total: Arc::new(Mutex::new(0)),
            progress_done: Arc::new(Mutex::new(0)),
            progress_err: Arc::new(Mutex::new(0)),
        }
    }

    /// 等待所有 spawn 的任务执行完
    pub async fn wait_all(&self) {
        let mut set = self.joinset.lock().unwrap();
        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                eprintln!("后台任务 panic: {}", e);
            }
        }
    }

    pub async fn lock(&self) {
        let j = self.joinset.clone();

        if let Err(e) = scan_files_iterative(&self.paths, move |file_path| {
            let sem = self.semaphore.clone();
            let pwd2 = self.password.clone();
            let locker2 = self.locker.clone();
            let progress_total = self.progress_total.clone();
            let progress_done = self.progress_done.clone();
            let progress_err = self.progress_err.clone();

            *progress_total.lock().unwrap() += 1;

            // 把任务加入 JoinSet
            let mut set = j.lock().unwrap();
            set.spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");

                if let Err(e) = locker2.lock(file_path, pwd2).await {
                    *progress_err.lock().unwrap() += 1;
                    eprintln!("加密文件时出错: {}", e);
                }else{
                    *progress_done.lock().unwrap() += 1;
                }
            });
        }).await {
            eprintln!("扫描目录时出错: {}", e);
        }

        // 等待全部完成
        self.wait_all().await;
    }

    pub async fn unlock(&self) {
        let j = self.joinset.clone();

        if let Err(e) = scan_files_iterative(&self.paths, move |file_path| {
            let sem = self.semaphore.clone();
            let pwd2 = self.password.clone();
            let locker2 = self.locker.clone();
            let progress_total = self.progress_total.clone();
            let progress_done = self.progress_done.clone();
            let progress_err = self.progress_err.clone();

            *progress_total.lock().unwrap() += 1;
            
            let mut set = j.lock().unwrap();
            set.spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");

                if let Err(e) = locker2.unlock(file_path, pwd2).await {
                    *progress_err.lock().unwrap() += 1;
                    eprintln!("解密文件时出错: {}", e);
                }else{
                    *progress_done.lock().unwrap() += 1;
                }
            });
        }).await {
            eprintln!("扫描目录时出错: {}", e);
        }

        // 等待全部完成
        self.wait_all().await;
    }

    pub fn get_total_count(&self) -> u64 {
        *self.progress_total.lock().unwrap()
    }

    pub fn get_done_count(&self) -> u64 {
         *self.progress_done.lock().unwrap()
    }

    pub fn get_err_count(&self) -> u64 {
         *self.progress_err.lock().unwrap()
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