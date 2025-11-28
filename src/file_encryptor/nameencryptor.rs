use std::{path::PathBuf};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::fs;
const LOCK_PREFIX: &str = "$$";
const MAX_FILENAME_LEN: usize = 255;
const BASE64_RNGINE: base64::engine::GeneralPurpose = URL_SAFE_NO_PAD;

/// 正向字符 remap - 支持所有base64字符的随机映射
fn base64_forward_remap(input: &str) -> String {
    input.chars().map(|c| {
        match c {
            'A' => 'm', 'B' => 'Q', 'C' => 'x', 'D' => '7', 'E' => 'k', 'F' => 'T',
            'G' => 'b', 'H' => '2', 'I' => 'W', 'J' => 'f', 'K' => 'y', 'L' => 'P',
            'M' => 'a', 'N' => '9', 'O' => 'L', 'P' => 'v', 'Q' => 'g', 'R' => '4',
            'S' => 'h', 'T' => 'D', 'U' => 'z', 'V' => '6', 'W' => 'E', 'X' => 'n',
            'Y' => '0', 'Z' => 'R', 'a' => 'c', 'b' => 'J', 'c' => '5', 'd' => 'u',
            'e' => 'S', 'f' => '8', 'g' => 'p', 'h' => 'V', 'i' => '3', 'j' => 'F',
            'k' => 'r', 'l' => 'B', 'm' => 't', 'n' => '1', 'o' => 'M', 'p' => 'w',
            'q' => 'A', 'r' => 'G', 's' => 'd', 't' => 'H', 'u' => 'i', 'v' => 'Y',
            'w' => 'j', 'x' => 'K', 'y' => 'N', 'z' => 'e', '0' => 'l', '1' => 'X',
            '2' => 'o', '3' => 'C', '4' => 'q', '5' => 'I', '6' => 'U', '7' => 'O',
            '8' => 's', '9' => 'Z', '+' => '/', '/' => '+',
            _ => c
        }
    }).collect()
}

/// 反向字符 remap - 对应的反向映射
fn base64_reverse_remap(input: &str) -> String {
    input.chars().map(|c| {
        match c {
            'm' => 'A', 'Q' => 'B', 'x' => 'C', '7' => 'D', 'k' => 'E', 'T' => 'F',
            'b' => 'G', '2' => 'H', 'W' => 'I', 'f' => 'J', 'y' => 'K', 'P' => 'L',
            'a' => 'M', '9' => 'N', 'L' => 'O', 'v' => 'P', 'g' => 'Q', '4' => 'R',
            'h' => 'S', 'D' => 'T', 'z' => 'U', '6' => 'V', 'E' => 'W', 'n' => 'X',
            '0' => 'Y', 'R' => 'Z', 'c' => 'a', 'J' => 'b', '5' => 'c', 'u' => 'd',
            'S' => 'e', '8' => 'f', 'p' => 'g', 'V' => 'h', '3' => 'i', 'F' => 'j',
            'r' => 'k', 'B' => 'l', 't' => 'm', '1' => 'n', 'M' => 'o', 'w' => 'p',
            'A' => 'q', 'G' => 'r', 'd' => 's', 'H' => 't', 'i' => 'u', 'Y' => 'v',
            'j' => 'w', 'K' => 'x', 'N' => 'y', 'e' => 'z', 'l' => '0', 'X' => '1',
            'o' => '2', 'C' => '3', 'q' => '4', 'I' => '5', 'U' => '6', 'O' => '7',
            's' => '8', 'Z' => '9', '/' => '+', '+' => '/',
            _ => c
        }
    }).collect()
}

/// 字符串加密
fn try_lockname(original: &str) -> Result<String, String> {
    if original.starts_with(LOCK_PREFIX) {
        return Ok(original.to_string());
    }
    let enc = BASE64_RNGINE.encode(original.as_bytes());
    // remap
    let enc = base64_forward_remap(&enc);

    let locked_name = format!("{}{}", LOCK_PREFIX, enc);

    if locked_name.len() > MAX_FILENAME_LEN {
        return Err(format!("名称太长无法加密: {}", original));
    }

    Ok(locked_name)
}

/// 字符串解密
fn try_unlockname(name: &str) -> Result<String, String> {
    if !name.starts_with(LOCK_PREFIX) {
        return Ok(name.to_string());
    }
    let b64 = &name[LOCK_PREFIX.len()..];
    // deremap
    let b64 = base64_reverse_remap(b64);
    let decoded = BASE64_RNGINE
        .decode(b64)
        .map_err(|e| format!("base64 decode error: {}", e))?;
    String::from_utf8(decoded).map_err(|e| format!("utf8 error: {}", e))
}

/// 对 PathBuf 的文件名或目录名加密（处理最后一级，返回新的 PathBuf）
fn try_lock_path(path: &PathBuf) -> Result<PathBuf, String> {
    let parent = path.parent();
    let name = path.file_name()
        .ok_or("missing filename or directory name")?
        .to_string_lossy();
    let new_name = try_lockname(&name)?;
    Ok(match parent {
        Some(p) => p.join(new_name),
        None => PathBuf::from(new_name),
    })
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
    let locked_path = try_lock_path(path)?;
    if path.exists() && path != &locked_path {
        fs::rename(path, &locked_path)
            .map_err(|e| format!("混淆错误: {}", e))?;
    }
    Ok(locked_path)
}

/// 在文件系统上对路径进行解密（重命名文件/目录）
pub fn unlock_pathname_on_fs(path: &PathBuf) -> Result<PathBuf, String> {
    let unlocked_path = try_unlock_path(path)?;
    if path.exists() && path != &unlocked_path {
        fs::rename(path, &unlocked_path)
            .map_err(|e| format!("混淆错误: {}", e))?;
    }
    Ok(unlocked_path)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const BASE64_CHARS: &[char] = &[
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    ];

    #[test]
    fn test_forward_remap_coverage() {
        // 测试所有base64字符都有映射
        for &ch in BASE64_CHARS {
            let remapped = base64_forward_remap(&ch.to_string());
            assert!(!remapped.is_empty(), "Character '{}' should have a mapping", ch);
            assert_ne!(remapped.chars().next().unwrap(), ch, 
                      "Character '{}' should not map to itself (check if this is intended)", ch);
        }
    }

    #[test]
    fn test_forward_remap_uniqueness() {
        // 测试所有映射都是唯一的
        let mut mappings = std::collections::HashSet::new();
        
        for &ch in BASE64_CHARS {
            let remapped = base64_forward_remap(&ch.to_string());
            let mapped_char = remapped.chars().next().unwrap();
            
            assert!(!mappings.contains(&mapped_char), 
                   "Duplicate mapping found: '{}' maps to '{}' which is already used", 
                   ch, mapped_char);
            mappings.insert(mapped_char);
        }
        
        // 确保映射数量正确
        assert_eq!(mappings.len(), 64, "Should have exactly 64 unique mappings");
    }

    #[test]
    fn test_reverse_remap_coverage() {
        // 测试反向映射覆盖所有base64字符
        for &ch in BASE64_CHARS {
            let remapped = base64_reverse_remap(&ch.to_string());
            assert!(!remapped.is_empty(), "Character '{}' should have a reverse mapping", ch);
        }
    }

    #[test]
    fn test_reverse_remap_uniqueness() {
        // 测试反向映射都是唯一的
        let mut mappings = std::collections::HashSet::new();
        
        for &ch in BASE64_CHARS {
            let remapped = base64_reverse_remap(&ch.to_string());
            let mapped_char = remapped.chars().next().unwrap();
            
            assert!(!mappings.contains(&mapped_char), 
                   "Duplicate reverse mapping found: '{}' maps to '{}' which is already used", 
                   ch, mapped_char);
            mappings.insert(mapped_char);
        }
        
        assert_eq!(mappings.len(), 64, "Should have exactly 64 unique reverse mappings");
    }

    #[test]
    fn test_forward_reverse_consistency() {
        // 测试正向和反向映射的一致性
        for &ch in BASE64_CHARS {
            let forward = base64_forward_remap(&ch.to_string());
            let forward_char = forward.chars().next().unwrap();
            
            let reverse = base64_reverse_remap(&forward_char.to_string());
            let reverse_char = reverse.chars().next().unwrap();
            
            assert_eq!(reverse_char, ch, 
                      "Forward-Forward consistency failed: '{}' -> '{}' -> '{}'", 
                      ch, forward_char, reverse_char);
        }
    }

    #[test]
    fn test_reverse_forward_consistency() {
        // 测试反向和正向映射的一致性
        for &ch in BASE64_CHARS {
            let reverse = base64_reverse_remap(&ch.to_string());
            let reverse_char = reverse.chars().next().unwrap();
            
            let forward = base64_forward_remap(&reverse_char.to_string());
            let forward_char = forward.chars().next().unwrap();
            
            assert_eq!(forward_char, ch, 
                      "Reverse-Forward consistency failed: '{}' -> '{}' -> '{}'", 
                      ch, reverse_char, forward_char);
        }
    }

    #[test]
    fn test_randomness() {
        // 测试映射的随机性（不是简单的顺序排列）
        let forward_mappings: Vec<char> = BASE64_CHARS.iter()
            .map(|&ch| base64_forward_remap(&ch.to_string()).chars().next().unwrap())
            .collect();
        
        // 检查不是简单的顺序排列
        let mut sequential_count = 0;
        for i in 1..forward_mappings.len() {
            if forward_mappings[i] as u8 == forward_mappings[i-1] as u8 + 1 {
                sequential_count += 1;
            }
        }
        
        // 如果超过一半是连续的，说明不够随机
        assert!(sequential_count < 32, 
               "Mapping appears too sequential: {} out of 64 are consecutive", 
               sequential_count);
        
        // 检查不是简单的移位
        let shift_patterns = [1, 2, 3, 4, 5, 6, 7, 8, 16, 32];
        for &shift in &shift_patterns {
            let mut all_shifted = true;
            for (i, &ch) in BASE64_CHARS.iter().enumerate() {
                let expected = BASE64_CHARS[(i + shift) % 64];
                let actual = base64_forward_remap(&ch.to_string()).chars().next().unwrap();
                if actual != expected {
                    all_shifted = false;
                    break;
                }
            }
            assert!(!all_shifted, "Mapping appears to be a simple shift by {}", shift);
        }
    }

    #[test]
    fn test_all_base64_chars_in_output() {
        // 测试输出包含所有base64字符
        let forward_mappings: Vec<char> = BASE64_CHARS.iter()
            .map(|&ch| base64_forward_remap(&ch.to_string()).chars().next().unwrap())
            .collect();
        
        let output_set: std::collections::HashSet<_> = forward_mappings.iter().collect();
        
        for &ch in BASE64_CHARS {
            assert!(output_set.contains(&ch), 
                   "Output missing base64 character '{}'", ch);
        }
        
        assert_eq!(output_set.len(), 64, "Output should contain exactly 64 unique characters");
    }

    #[test]
    fn test_round_trip() {
        // 测试完整的往返转换
        let test_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let encoded = base64_forward_remap(test_string);
        let decoded = base64_reverse_remap(&encoded);
        
        assert_eq!(decoded, test_string, "Round trip conversion failed");
    }

    #[test]
    fn test_edge_cases() {
        // 测试边界情况
        assert_eq!(base64_forward_remap(""), "");
        assert_eq!(base64_reverse_remap(""), "");
        
        // 测试非base64字符（应该保持不变）
        let non_base64 = "!@#$%^&*()[]{}|\\:;\"'<>,.?~`";
        assert_eq!(base64_forward_remap(non_base64), non_base64);
        assert_eq!(base64_reverse_remap(non_base64), non_base64);
    }

    #[test]
    fn test_file_lock_unlock() {
        let original = PathBuf::from("example.txt");
        let locked = try_lock_path(&original).unwrap();
        assert!(locked.file_name().unwrap().to_string_lossy().starts_with(LOCK_PREFIX));
        let unlocked = try_unlock_path(&locked).expect("should decode");
        assert_eq!(original, unlocked);
    }

    #[test]
    fn test_dir_lock_unlock() {
        let original = PathBuf::from("测试目录");
        let locked = try_lock_path(&original).unwrap();
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