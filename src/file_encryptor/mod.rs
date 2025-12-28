pub mod base;
pub use base::DirLockManager;
pub mod simple_encryptor;
pub use simple_encryptor::SimpleEncryptor;
pub mod aes_encryptor;
pub use aes_encryptor::AesEncryptor;
pub mod chacha20_encryptor;
pub use chacha20_encryptor::ChaChaEncryptor;
pub mod nameencryptor;
pub mod not_all_encryptor;
pub use not_all_encryptor::NotAllEncryptor;

#[derive(Debug, Clone, PartialEq)]
pub enum LockMethod {
    Simple,
    Aes,
    Chacha20,
    NotAll,
}

impl LockMethod {
    pub fn new_encryptor_manager(&self, dir_path: Vec<String>, password: String) -> DirLockManager {
        match self {
            LockMethod::Simple => {
                DirLockManager::new(dir_path, password, SimpleEncryptor::new())
            }
            LockMethod::Aes => {
                DirLockManager::new(dir_path, password, AesEncryptor::new())
            }
            LockMethod::Chacha20 => {
                DirLockManager::new(dir_path, password, ChaChaEncryptor::new())
            }
            LockMethod::NotAll => {
                DirLockManager::new(dir_path, password, NotAllEncryptor::new())
            }
        }
    }
    pub fn display_name(&self) -> &str {
        match self {
            Self::Simple => "快速加密(无密码,非完全加密)",
            Self::Aes => "Aes(有硬件加速会较快,安全)",
            Self::Chacha20 => "Chacha20(无硬件加速,安全)",
            Self::NotAll => "部分随机加密(无密码)",
        }
    }
}