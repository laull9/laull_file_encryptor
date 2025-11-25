use std::path::{PathBuf};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::fs;

const LOCK_PREFIX: &str = "$$";

/// 字符串加密
fn try_lockname(original: &str) -> String {
    if original.starts_with(LOCK_PREFIX) {
        return original.to_string();
    }
    let enc = URL_SAFE_NO_PAD.encode(original.as_bytes());
    format!("{}{}", LOCK_PREFIX, enc)
}

/// 字符串解密
fn try_unlockname(name: &str) -> Result<String, String> {
    if !name.starts_with(LOCK_PREFIX) {
        return Ok(name.to_string());
    }
    let b64 = &name[LOCK_PREFIX.len()..];
    let decoded = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("base64 decode error: {}", e))?;
    String::from_utf8(decoded).map_err(|e| format!("utf8 error: {}", e))
}

/// 对 PathBuf 的文件名或目录名加密（处理最后一级，返回新的 PathBuf）
fn try_lock_path(path: &PathBuf) -> PathBuf {
    let parent = path.parent();
    let name = path.file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let new_name = try_lockname(&name);
    match parent {
        Some(p) => p.join(new_name),
        None => PathBuf::from(new_name),
    }
}

/// 对 PathBuf 的文件名或目录名解密（处理最后一级）
fn try_unlock_path(path: &PathBuf) -> Result<PathBuf, String> {
    let parent = path.parent();
    let name = path.file_name()
        .ok_or("missing filename or directory name")?
        .to_string_lossy();
    let new_name = try_unlockname(&name)?;
    Ok(match parent {
        Some(p) => p.join(new_name),
        None => PathBuf::from(new_name),
    })
}

/// 在文件系统上对路径进行加密（重命名文件/目录）
pub fn lock_pathname_on_fs(path: &PathBuf) -> Result<PathBuf, String> {
    let locked_path = try_lock_path(path);
    if path.exists() && path != &locked_path {
        fs::rename(path, &locked_path)
            .map_err(|e| format!("fs rename error: {}", e))?;
    }
    Ok(locked_path)
}

/// 在文件系统上对路径进行解密（重命名文件/目录）
pub fn unlock_pathname_on_fs(path: &PathBuf) -> Result<PathBuf, String> {
    let unlocked_path = try_unlock_path(path)?;
    if path.exists() && path != &unlocked_path {
        fs::rename(path, &unlocked_path)
            .map_err(|e| format!("fs rename error: {}", e))?;
    }
    Ok(unlocked_path)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_file_lock_unlock() {
        let original = PathBuf::from("example.txt");
        let locked = try_lock_path(&original);
        assert!(locked.file_name().unwrap().to_string_lossy().starts_with(LOCK_PREFIX));
        let unlocked = try_unlock_path(&locked).expect("should decode");
        assert_eq!(original, unlocked);
    }

    #[test]
    fn test_dir_lock_unlock() {
        let original = PathBuf::from("测试目录");
        let locked = try_lock_path(&original);
        assert!(locked.file_name().unwrap().to_string_lossy().starts_with(LOCK_PREFIX));
        let unlocked = try_unlock_path(&locked).expect("should decode");
        assert_eq!(original, unlocked);
    }

    #[test]
    fn test_real_file_rename() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("example.txt");
        fs::write(&file_path, b"test").unwrap();

        let locked_path = lock_pathname_on_fs(&file_path).unwrap();
        assert!(locked_path.exists());
        assert!(locked_path.file_name().unwrap().to_string_lossy().starts_with(LOCK_PREFIX));

        let unlocked_path = unlock_pathname_on_fs(&locked_path).unwrap();
        assert!(unlocked_path.exists());
        assert_eq!(unlocked_path.file_name().unwrap(), "example.txt");
    }

    #[test]
    fn test_real_dir_rename() {
        let dir = tempdir().unwrap();
        let sub_dir = dir.path().join("子目录");
        fs::create_dir(&sub_dir).unwrap();

        let locked_dir = lock_pathname_on_fs(&sub_dir).unwrap();
        assert!(locked_dir.exists());
        assert!(locked_dir.file_name().unwrap().to_string_lossy().starts_with(LOCK_PREFIX));

        let unlocked_dir = unlock_pathname_on_fs(&locked_dir).unwrap();
        assert!(unlocked_dir.exists());
        assert_eq!(unlocked_dir.file_name().unwrap(), "子目录");
    }
}
