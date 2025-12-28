use super::base::Encryptor;
use async_trait::async_trait;
use std::path::{Path, PathBuf};

const REPLACE_FILE_LEN: u64 = 1024;
const ENCRYPT_RATIO: f64 = 0.01; // 1%

pub struct NotAllEncryptor;

impl NotAllEncryptor {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Encryptor for NotAllEncryptor {
    fn encryptor_id(&self) -> [u8; 4] {
        *b"NOTA"
    }

    async fn lock_inner(&self, filepath: PathBuf, _password: String) -> tokio::io::Result<()> {
        file_lock_unlock_async(&filepath, self.encryptor_id()).await
    }

    async fn unlock_inner(&self, filepath: PathBuf, _password: String) -> tokio::io::Result<()> {
        file_lock_unlock_async(&filepath, self.encryptor_id()).await
    }
}


pub async fn file_lock_unlock_async<P: AsRef<Path>>(
    path: P,
    algo_id: [u8; 4],
) -> tokio::io::Result<()> {
    let mut file = tokio::fs::File::options()
        .read(true)
        .write(true)
        .open(&path)
        .await?;

    let file_size = file.metadata().await?.len();
    if file_size == 0 {
        return Ok(());
    }

    let block = REPLACE_FILE_LEN;
    let blocks_to_encrypt =
        ((file_size as f64 * ENCRYPT_RATIO) / block as f64)
            .ceil()
            .max(1.0) as u64;

    /* === 1. 文件头（永远处理） === */
    process_block(&mut file, 0, block).await?;

    /* === 2. 固定伪随机偏移 === */
    let seed = build_seed(file_size, algo_id);
    let offsets = generate_offsets(file_size, block, blocks_to_encrypt, seed);

    for offset in offsets {
        if offset + block <= file_size {
            process_block(&mut file, offset, block).await?;
        }
    }

    Ok(())
}

/* =========================
 * Block 处理（可逆）
 * ========================= */

async fn process_block(
    file: &mut tokio::fs::File,
    offset: u64,
    block_size: u64,
) -> tokio::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    const STACK_BUF_LEN: usize = REPLACE_FILE_LEN as usize;
    let mut stack_buf = [0u8; STACK_BUF_LEN];

    file.seek(tokio::io::SeekFrom::Start(offset)).await?;

    if (block_size as usize) <= STACK_BUF_LEN {
        // 使用栈缓冲区以避免堆分配
        let n = file.read(&mut stack_buf[..block_size as usize]).await?;
        let buf = &mut stack_buf[..n];

        // 可逆扰动（非密码学）
        buf.reverse();
        for b in buf.iter_mut() {
            *b = u8::MAX - *b;
        }

        file.seek(tokio::io::SeekFrom::Start(offset)).await?;
        file.write_all(buf).await?;
    } else {
        // 大于常量时仍然使用堆分配
        let mut buf = vec![0u8; block_size as usize];
        let n = file.read(&mut buf).await?;
        buf.truncate(n);

        buf.reverse();
        for b in &mut buf {
            *b = u8::MAX - *b;
        }

        file.seek(tokio::io::SeekFrom::Start(offset)).await?;
        file.write_all(&buf).await?;
    }

    Ok(())
}

/* =========================
 * 固定伪随机 offset 生成
 * ========================= */

fn generate_offsets(
    file_size: u64,
    block: u64,
    count: u64,
    seed: u64,
) -> Vec<u64> {
    // 如果文件小于等于一个块，则无法生成有效偏移
    if file_size <= block {
        return Vec::new();
    }

    // 最大块索引（从 0 开始），offset = index * block
    let max_block_index = (file_size - block) / block; // >= 1
    // 可用的非零索引数量（1..=max_block_index）
    let available = max_block_index as usize;
    if available == 0 {
        return Vec::new();
    }
    let desired = std::cmp::min(count as usize, available);

    use std::collections::HashSet;

    let mut rng = SplitMix64::new(seed);
    // 预分配容量以避免再分配
    let mut chosen: HashSet<u64> = HashSet::with_capacity(desired);
    // 随机选择块索引（排除 index == 0，因文件头已处理）
    while chosen.len() < desired {
        let idx = (rng.next() % (max_block_index + 1)) as u64; // 0..=max_block_index
        if idx != 0 {
            chosen.insert(idx);
        }
    }

    // 映射为偏移并排序以获得稳定输出
    let mut offsets: Vec<u64> = chosen.into_iter().map(|idx| idx * block).collect();
    offsets.sort_unstable();
    offsets
}

/* =========================
 * Seed 构造（无 password）
 * ========================= */

fn build_seed(file_size: u64, algo_id: [u8; 4]) -> u64 {
    let mut seed = file_size;
    let id = u32::from_be_bytes(algo_id) as u64;

    // 简单但足够的 avalanche
    seed ^= id.rotate_left(17);
    seed = seed.wrapping_mul(0x9E3779B97F4A7C15);
    seed ^= seed >> 32;
    seed
}

/* =========================
 * SplitMix64 PRNG
 * ========================= */

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        let mut z = self.state.wrapping_add(0x9E3779B97F4A7C15);
        self.state = z;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::{Write, Read};

    // SplitMix64
    #[test]
    fn test_splitmix64_deterministic() {
        let mut rng1 = SplitMix64::new(12345);
        let mut rng2 = SplitMix64::new(12345);

        for _ in 0..100 {
            assert_eq!(rng1.next(), rng2.next());
        }
    }

    // Seed 构造
    #[test]
    fn test_build_seed_stable() {
        let seed1 = build_seed(1024, *b"NOTA");
        let seed2 = build_seed(1024, *b"NOTA");
        let seed3 = build_seed(2048, *b"NOTA");

        assert_eq!(seed1, seed2);
        assert_ne!(seed1, seed3);
    }

    // Offset 生成
    #[test]
    fn test_generate_offsets_properties() {
        let file_size = 1024 * 100;
        let block = 1024;
        let count = 10;
        let seed = 42;

        let offsets = generate_offsets(file_size, block, count, seed);

        assert_eq!(offsets.len(), count as usize);

        // 不重复
        for (i, a) in offsets.iter().enumerate() {
            for b in offsets.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }

        // 对齐 block，且不为 0
        for &o in &offsets {
            assert_eq!(o % block, 0);
            assert_ne!(o, 0);
            assert!(o + block <= file_size);
        }
    }

    // 边界情况：文件大小等于块大小
    #[test]
    fn test_generate_offsets_file_size_equals_block() {
        let file_size = 1024;
        let block = 1024;
        let count = 10;
        let seed = 42;

        let offsets = generate_offsets(file_size, block, count, seed);

        // 当文件大小等于块大小时，无法生成有效偏移
        assert_eq!(offsets.len(), 0);
    }

    // 边界情况：文件大小小于块大小
    #[test]
    fn test_generate_offsets_file_size_less_than_block() {
        let file_size = 512;
        let block = 1024;
        let count = 10;
        let seed = 42;

        let offsets = generate_offsets(file_size, block, count, seed);

        // 当文件大小小于块大小时，无法生成有效偏移
        assert_eq!(offsets.len(), 0);
    }

    // 边界情况：文件大小略大于块大小
    #[test]
    fn test_generate_offsets_file_size_slightly_larger_than_block() {
        let file_size = 1024 * 2;
        let block = 1024;
        let count = 2;
        let seed = 42;

        let offsets = generate_offsets(file_size, block, count, seed);

        // 应能生成有效偏移
        assert!(offsets.len() <= count as usize);
        for &o in &offsets {
            assert!(o + block <= file_size);
        }
    }

    // 空文件情况
    #[test]
    fn test_generate_offsets_empty_file() {
        let file_size = 0;
        let block = 1024;
        let count = 10;
        let seed = 42;

        let offsets = generate_offsets(file_size, block, count, seed);

        assert_eq!(offsets.len(), 0);
    }

    // Block 可逆性
    #[tokio::test]
    async fn test_process_block_reversible() {
        let mut file = NamedTempFile::new().unwrap();

        let data: Vec<u8> = (0..255).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let mut tokio_file = tokio::fs::File::options()
            .read(true)
            .write(true)
            .open(file.path())
            .await
            .unwrap();

        process_block(&mut tokio_file, 0, data.len() as u64).await.unwrap();
        process_block(&mut tokio_file, 0, data.len() as u64).await.unwrap();

        // 显式同步并关闭 tokio_file，确保数据写入磁盘
        tokio_file.sync_all().await.unwrap();
        drop(tokio_file);

        let mut result = Vec::new();
        file.reopen().unwrap().read_to_end(&mut result).unwrap();

        assert_eq!(data, result);
    }

    // 全流程加解密
    #[tokio::test]
    async fn test_file_lock_unlock_roundtrip() {
        let mut file = NamedTempFile::new().unwrap();

        let original: Vec<u8> = (0..100_000)
            .map(|i| (i % 256) as u8)
            .collect();

        file.write_all(&original).unwrap();
        file.flush().unwrap();

        let path = file.path();

        // 加密
        file_lock_unlock_async(path, *b"NOTA")
            .await
            .unwrap();

        // 解密
        file_lock_unlock_async(path, *b"NOTA")
            .await
            .unwrap();

        let mut result = Vec::new();
        file.reopen().unwrap().read_to_end(&mut result).unwrap();

        assert_eq!(original, result);
    }

    // 小文件加解密（边界情况）
    #[tokio::test]
    async fn test_file_lock_unlock_small_file() {
        let mut file = NamedTempFile::new().unwrap();

        let original: Vec<u8> = (0..512)
            .map(|i| (i % 256) as u8)
            .collect();

        file.write_all(&original).unwrap();
        file.flush().unwrap();

        let path = file.path();

        // 加密（应处理头部块，但不会生成额外偏移）
        file_lock_unlock_async(path, *b"NOTA")
            .await
            .unwrap();

        // 解密
        file_lock_unlock_async(path, *b"NOTA")
            .await
            .unwrap();

        let mut result = Vec::new();
        file.reopen().unwrap().read_to_end(&mut result).unwrap();

        assert_eq!(original, result);
    }

    // 空文件加解密
    #[tokio::test]
    async fn test_file_lock_unlock_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();

        // 空文件应该不出错
        file_lock_unlock_async(path, *b"NOTA")
            .await
            .unwrap();
    }
}