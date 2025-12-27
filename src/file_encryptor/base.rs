use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use tokio::task::JoinSet;
use tokio::sync::{Semaphore, Mutex as AsyncMutex};
use async_trait::async_trait;
use tracing::{error};

use super::nameencryptor::{lock_pathname_on_fs, unlock_pathname_on_fs};

type HmacSha256 = Hmac<Sha256>;
const MAX_CONCURRENT: usize = 16;

const TRAITER_ID_LEN: usize = 4;
const TRAITER_TAG_LEN: usize = 32;
const TRAILER_FINISH_TAG: [u8; 8] = *b";;!FQ!;;";
const TRAILER_FINISH_TAG_LEN: usize = 8;
const TRAILER_LEN: usize = TRAITER_ID_LEN + TRAITER_TAG_LEN + TRAILER_FINISH_TAG_LEN;

const HEADER_LEN: usize = 1024;    // read first 1KB to compute tag

#[derive(Clone, Copy)]
pub struct ScanOptions {
    pub(crate) include_input_dirs: bool,
    pub(crate) recursive: bool,
}

pub async fn scan_files_iterative(
    paths: &Vec<String>,
    scan_options: ScanOptions,
    err_buf: Arc<AsyncMutex<Vec<String>>>,
) -> tokio::io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut found_files = Vec::new();
    let mut found_dirs = Vec::new();

    let mut queue = VecDeque::new();       // BFS 队列
    let mut visited = HashSet::new();      // 防止递归重复

    let mut input_dirs = HashSet::new();   // 用于过滤输入目录

    /* ---------- 初始化输入路径 ---------- */
    for path_str in paths {
        let path = Path::new(path_str).to_path_buf();

        let meta = match fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) => {
                err_buf.lock().await.push(format!(
                    "路径 '{}' 无法访问: {}", path.display(), e
                ));
                continue;
            }
        };

        if meta.is_file() {
            found_files.push(path);
        } else if meta.is_dir() {
            let canon = path.canonicalize().unwrap_or(path.clone());

            input_dirs.insert(canon.clone());
            visited.insert(canon.clone());
            queue.push_back(canon.clone());

            if scan_options.include_input_dirs {
                found_dirs.push(canon);
            }
        }
    }

    /* ---------- BFS 扫描 ---------- */
    while let Some(current_dir) = queue.pop_front() {
        let mut entries = match fs::read_dir(&current_dir).await {
            Ok(e) => e,
            Err(e) => {
                err_buf.lock().await.push(format!(
                    "无法读取目录 '{}': {}", current_dir.display(), e
                ));
                continue;
            }
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let meta = match fs::metadata(&path).await {
                Ok(m) => m,
                Err(_) => continue,
            };

            if meta.is_file() {
                found_files.push(path);
            } else if meta.is_dir() {
                // 非递归：完全忽略子目录
                if !scan_options.recursive {
                    continue;
                }

                let canon = path.canonicalize().unwrap_or(path.clone());

                // 递归：去重后继续向下
                if visited.insert(canon.clone()) {
                    found_dirs.push(canon.clone());
                    queue.push_back(canon);
                }
            }
        }
    }

    /* ---------- 是否过滤输入目录 ---------- */
    let final_dirs = if scan_options.include_input_dirs {
        found_dirs
    } else {
        found_dirs
            .into_iter()
            .filter(|d| !input_dirs.contains(d))
            .collect()
    };

    Ok((found_files, final_dirs))
}


#[async_trait]
pub trait Encryptor: Send + Sync + 'static {
    // 每个 encryptor 返回自己的 ID（改为方法以支持 trait 对象）
    fn encryptor_id(&self) -> [u8; TRAITER_ID_LEN];
    async fn lock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()>;
    async fn unlock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()>;
    async fn is_locked(&self, filepath: PathBuf) 
        -> tokio::io::Result<bool>
    {
        Ok(read_trailer_if_exists(filepath).await?.is_some())
    }


    async fn lock(&self, filepath: &PathBuf, password: String) 
        -> tokio::io::Result<()>
    {
        if self.is_locked(filepath.clone()).await? {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::AlreadyExists,
                "文件已被加密",
            ));
        }
        self.lock_inner(filepath.clone(), password.clone()).await?;
        write_trailer(&filepath, self.encryptor_id(), &password).await
    }

    async fn unlock(&self, filepath: &PathBuf, password: String) 
        -> tokio::io::Result<()>
    {
        if !verify_trailer(&filepath, self.encryptor_id(), &password).await? {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "密码错误或者解密方式错误",
            ));
        }
        remove_trailer(&filepath).await?;
        self.unlock_inner(filepath.clone(), password).await
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


// 写尾标：encryptor_id + tag
pub async fn write_trailer<P: AsRef<Path>>(
    path: P, encryptor_id: [u8;TRAITER_ID_LEN], password: &str
) -> tokio::io::Result<()> {

    // 打开可读写的同一个文件句柄（后续不再 reopen）
    let path_ref = path.as_ref();
    let mut file = File::options().read(true).write(true).open(path_ref).await?;
    let mut meta = file.metadata().await?;
    let file_len = meta.len();

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

    // 追加尾标（encryptor_id + tag + finish_tag）
    file.seek(std::io::SeekFrom::End(0)).await?;
    file.write_all(&encryptor_id).await?;
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

    let encryptor_id: [u8; TRAITER_ID_LEN] = buf[..TRAITER_ID_LEN].try_into().unwrap();
    let tag: [u8; 32] = buf[TRAITER_ID_LEN..(TRAITER_ID_LEN + TRAITER_TAG_LEN)].try_into().unwrap();
    let finish_tag: [u8; 8] = buf[(TRAITER_ID_LEN + TRAITER_TAG_LEN)..].try_into().unwrap();
    if finish_tag != TRAILER_FINISH_TAG {
        return Ok(None);
    }

    Ok(Some((encryptor_id, tag)))
}

// 验证尾标
pub async fn verify_trailer<P: AsRef<Path>>(
    path: P, expected_encryptor_id: [u8;4], password: &str
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

    let stored_encryptor_id: [u8; TRAITER_ID_LEN] = buf[..TRAITER_ID_LEN].try_into().unwrap();
    if stored_encryptor_id != expected_encryptor_id {
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

#[derive(Clone)]
pub struct DirLockManager {
    semaphore: Arc<Semaphore>,
    paths: Vec<String>,
    password: Arc<String>,
    encryptor: Arc<dyn Encryptor + 'static>,
    joinset: Arc<AsyncMutex<JoinSet<()>>>,
    progress_total: Arc<AtomicU64>,
    progress_done: Arc<AtomicU64>,
    progress_err: Arc<AtomicU64>,
    is_done: Arc<AtomicBool>,
    scan_options: ScanOptions,
}

impl DirLockManager {
    pub fn new<L>(dir_path: Vec<String>, password: String, encryptor: L) -> Self
    where
        L: Encryptor + 'static
    {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            paths: dir_path,
            password: Arc::new(password),
            encryptor: Arc::new(encryptor),
            joinset: Arc::new(AsyncMutex::new(JoinSet::new())),
            progress_total: Arc::new(AtomicU64::new(0)),
            progress_done: Arc::new(AtomicU64::new(0)),
            progress_err: Arc::new(AtomicU64::new(0)),
            is_done: Arc::new(AtomicBool::new(false)),
            scan_options: ScanOptions {
                include_input_dirs: false,
                recursive: true,
            }
        }
    }

    /// 等待所有 spawn 的任务执行完
    pub async fn wait_all_file_tasks(&self) {
        let mut set = self.joinset.clone().lock_owned().await;
        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                error!("后台任务 panic: {}", e);
            }
        }
        self.is_done.store(true, Ordering::SeqCst);
    }

    pub async fn lock(& self, process_filename: bool, process_dirname: bool) -> Vec<String> {
        let j = self.joinset.clone();
        let err_messages: Arc<AsyncMutex<Vec<String>>> = Arc::new(AsyncMutex::new(Vec::new()));

        let fd = scan_files_iterative(
            &self.paths, self.scan_options, err_messages.clone()
        ).await;
        if let Err(e) = &fd {
            let err = format!("扫描目录时出错: {}", e);
            error!("{}", &err);
            err_messages.lock().await.push(err);
            return err_messages.lock().await.to_vec();
        }
        let (files, dirs) = fd.unwrap();

        // 先设置总数（避免 race / 除零 / UI 无基数）
        self.progress_total.store(files.len() as u64, Ordering::SeqCst);
        // 重置 done / err（若需要）
        self.progress_done.store(0, Ordering::SeqCst);
        self.progress_err.store(0, Ordering::SeqCst);

        for file_path in files {
            let err_buf = err_messages.clone();
            let sem = self.semaphore.clone();
            let pwd2 = self.password.clone();
            let encryptor2 = self.encryptor.clone();
            let progress_done = self.progress_done.clone();
            let progress_err = self.progress_err.clone();

            // 获取 joinset guard 短生命周期地 spawn
            let mut set = j.lock().await;
            set.spawn(async move {
                // 先获取 permit（或先 inc total，已经预先设置了 total）
                let _permit = sem.acquire().await.expect("semaphore closed");

                if let Err(e) = encryptor2.lock(
                    &file_path, pwd2.as_ref().clone()
                ).await {
                    progress_err.fetch_add(1, Ordering::SeqCst);
                    let err = format!("加密文件: {:?}时出错: {}", &file_path, e);
                    error!("{}", &err);
                    err_buf.lock().await.push(err);
                } else {
                    progress_done.fetch_add(1, Ordering::SeqCst);
                }
                // 加密文件名
                if process_filename{
                    if let Err(e) = lock_pathname_on_fs(&file_path){
                        let err = format!("加密文件名: {:?}时出错: {}", &file_path, e);
                        error!("{}", &err);
                        err_buf.lock().await.push(err);
                    }
                }
            });
        }
        // 等待全部完成
        self.wait_all_file_tasks().await;

        if process_dirname{
            // 加密文件夹
            for dir in dirs.iter().rev(){
                if let Err(e) = lock_pathname_on_fs(dir){
                    let err = format!("加密文件夹: {:?}时出错: {}", &dir, e);
                    error!("{}", &err);
                    err_messages.lock().await.push(err);
                }
            }
        }

        err_messages.lock().await.to_vec()
    }

    pub async fn unlock(& self) -> Vec<String> {
        let j = self.joinset.clone();
        let err_messages: Arc<AsyncMutex<Vec<String>>> = 
            Arc::new(AsyncMutex::new(Vec::new()));


        let fd = scan_files_iterative(
            &self.paths, self.scan_options, err_messages.clone()).await;
        if let Err(e) = &fd {
            let err = format!("扫描目录时出错: {}", e);
            error!("{}", &err);
            err_messages.lock().await.push(err);
            return err_messages.lock().await.to_vec();
        }
        let (files,  dirs) = fd.unwrap();

        // 先设置总数（避免 race / 除零 / UI 无基数）
        self.progress_total.store(files.len() as u64, Ordering::SeqCst);
        // 重置 done / err（若需要）
        self.progress_done.store(0, Ordering::SeqCst);
        self.progress_err.store(0, Ordering::SeqCst);

        for file_path in files {
            let err_buf = err_messages.clone();
            let sem = self.semaphore.clone();
            let pwd2 = self.password.clone();
            let encryptor2 = self.encryptor.clone();
            let progress_done = self.progress_done.clone();
            let progress_err = self.progress_err.clone();

            // 获取 joinset guard 短生命周期地 spawn
            let mut set = j.lock().await;
            set.spawn(async move {
                // 先获取 permit（或先 inc total，已经预先设置了 total）
                let _permit = sem.acquire().await.expect("semaphore closed");

                if let Err(e) = encryptor2.unlock(&file_path, pwd2.as_ref().clone()).await {
                    progress_err.fetch_add(1, Ordering::SeqCst);
                    let err = format!("解密文件: {:?}时出错: {}", &file_path, e);
                    error!("{}", &err);
                    err_buf.lock().await.push(err);
                } else {
                    // 如果解密文件出错，那么不解密文件名
                    // 解密文件名
                    if let Err(e) = unlock_pathname_on_fs(&file_path){
                        let err = format!("解密文件名: {:?}时出错: {}", &file_path, e);
                        error!("{}", &err);
                        err_buf.lock().await.push(err); 
                    }
                    progress_done.fetch_add(1, Ordering::SeqCst);
                }

            });
        }
        // 等待全部完成
        self.wait_all_file_tasks().await;

        // 解密文件夹
        for dir in dirs.iter().rev(){
            if let Err(e) = unlock_pathname_on_fs(dir){
                let err = format!("解密文件夹: {:?}时出错: {}", &dir, e);
                error!("{}", &err);
                err_messages.lock().await.push(err);
            }
        }

        err_messages.lock().await.to_vec()
    }

    pub fn get_total_count(&self) -> u64 {
    self.progress_total.load(Ordering::SeqCst)
    }

    pub fn get_done_count(&self) -> u64 {
        self.progress_done.load(Ordering::SeqCst)
    }

    pub fn get_err_count(&self) -> u64 {
        self.progress_err.load(Ordering::SeqCst)
    }

    pub fn is_done(&self) -> bool {
        self.is_done.load(Ordering::SeqCst)
    }

    pub fn set_scan_options(self, options: ScanOptions) -> Self {
        Self {
            scan_options: options,
            ..self
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

        // wrong encryptor id -> false
        let ok2 = verify_trailer(&path, *b"WRNG", "secret").await.unwrap();
        assert!(!ok2, "verify_trailer with wrong encryptor id must be false");

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