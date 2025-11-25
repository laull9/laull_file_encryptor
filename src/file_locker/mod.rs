pub mod base;
pub use base::DirLockManager;
pub mod simple_locker;
pub use simple_locker::SimpleLocker;
pub mod aes_locker;
pub use aes_locker::AesLocker;
pub mod chacha20_locker;
pub use chacha20_locker::ChaChaLocker;
pub mod namelocker;

#[derive(Debug, Clone, PartialEq)]
pub enum LockMethod {
    Simple,
    Aes,
    Chacha20,
}

impl LockMethod {
    pub fn new_locker_manager(&self, dir_path: Vec<String>, password: String) -> DirLockManager {
        match self {
            LockMethod::Simple => {
                DirLockManager::new(dir_path, password, SimpleLocker::new())
            }
            LockMethod::Aes => {
                DirLockManager::new(dir_path, password, AesLocker::new())
            }
            LockMethod::Chacha20 => {
                DirLockManager::new(dir_path, password, ChaChaLocker::new())
            }
        }
    }
    pub fn display_name(&self) -> &str {
        match self {
            Self::Simple => "快速加密(非完全加密)",
            Self::Aes => "Aes(有硬件加速会较快,安全)",
            Self::Chacha20 => "Chacha20(无硬件加速，安全)",
        }
    }
}