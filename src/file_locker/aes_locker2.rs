use super::base::{Locker, compute_tag_with_len, write_trailer, read_trailer_if_exists, remove_trailer};
use ring::aead::{self, Aad, Nonce, UnboundKey, LessSafeKey, SealingKey, OpeningKey};
use ring::digest::{Context, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::fs::{File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::path::{Path, PathBuf};
use async_trait::async_trait;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;

const AES_BLOCK_SIZE: usize = 16; // AES block size in bytes
const AES_KEY_SIZE: usize = 32; // AES 256-bit key size

pub struct AesLocker {
    key: Vec<u8>, // Encryption key derived from password
}

impl AesLocker {
    pub fn new(password: &str) -> Self {
        let mut context = Context::new(&SHA256);
        context.update(password.as_bytes());
        let hash = context.finish();

        Self {
            key: hash.as_ref().to_vec(),
        }
    }

    fn generate_nonce(&self) -> [u8; AES_BLOCK_SIZE] {
        let mut nonce = [0u8; AES_BLOCK_SIZE];
        let rng = SystemRandom::new();
        rng.fill(&mut nonce).expect("Failed to generate nonce");
        nonce
    }

    fn encrypt_data(&self, data: &[u8]) -> Vec<u8> {
        let key = GenericArray::from_slice(&self.key);
        let cipher = Aes256::new(key);
        let mut encrypted = vec![0u8; data.len()];
        let mut buffer = data.to_vec();

        cipher.encrypt_block(GenericArray::from_mut_slice(&mut buffer));
        encrypted.clone_from_slice(&buffer);
        encrypted
    }

    fn decrypt_data(&self, data: &[u8]) -> Vec<u8> {
        let key = GenericArray::from_slice(&self.key);
        let cipher = Aes256::new(key);
        let mut decrypted = vec![0u8; data.len()];
        let mut buffer = data.to_vec();

        cipher.decrypt_block(GenericArray::from_mut_slice(&mut buffer));
        decrypted.clone_from_slice(&buffer);
        decrypted
    }
}

#[async_trait]
impl Locker for AesLocker {
    fn locker_id(&self) -> [u8; 4] {
        // Return a unique ID for this Locker (you can customize this as needed)
        *b"AES1"
    }

    async fn lock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        let mut file = File::options().read(true).write(true).open(&filepath).await?;
        let metadata = file.metadata().await?;
        let content_len = metadata.len();

        let mut buffer = vec![0u8; content_len as usize];
        file.read_exact(&mut buffer).await?;

        // Encrypt the data
        let encrypted_data = self.encrypt_data(&buffer);

        // Write the encrypted data back to the file
        file.set_len(0).await?; // Truncate the file
        file.write_all(&encrypted_data).await?;

        // Write the trailer with the locker id and tag
        write_trailer(filepath, self.locker_id(), &password).await?;

        Ok(())
    }

    async fn unlock_inner(&self, filepath: PathBuf, password: String) -> tokio::io::Result<()> {
        let mut file = File::options().read(true).open(&filepath).await?;
        let metadata = file.metadata().await?;
        let content_len = metadata.len();

        let mut buffer = vec![0u8; content_len as usize];
        file.read_exact(&mut buffer).await?;

        // Decrypt the data
        let decrypted_data = self.decrypt_data(&buffer);

        // Write the decrypted data back to the file
        file.set_len(0).await?; // Truncate the file
        file.write_all(&decrypted_data).await?;

        // Remove the trailer (if exists)
        remove_trailer(filepath).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;
    use std::path::Path;

    // Helper function to create a temporary file with content
    async fn create_temp_file(path: &str, content: &[u8]) -> tokio::io::Result<()> {
        let mut file = fs::File::create(path).await?;
        file.write_all(content).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_locker_lock_and_unlock() {
        let password = "password123";
        let locker = AesLocker::new(password);

        // Create a temporary file with test data
        let temp_path = Path::new("testfile.txt");
        let original_data = b"Hello, this is some test data that will be encrypted!";
        create_temp_file(temp_path.to_str().unwrap(), original_data).await.unwrap();

        // Lock the file (encrypt it)
        locker.lock_inner(temp_path.to_path_buf(), password.to_string()).await.unwrap();

        // Read the file after encryption
        let encrypted_data = fs::read(temp_path).await.unwrap();

        // Ensure the encrypted data is different from the original data
        assert_ne!(original_data, &encrypted_data[..]);

        // Unlock the file (decrypt it)
        locker.unlock_inner(temp_path.to_path_buf(), password.to_string()).await.unwrap();

        // Read the file after decryption
        let decrypted_data = fs::read(temp_path).await.unwrap();

        // Ensure the decrypted data matches the original data
        assert_eq!(original_data, &decrypted_data[..]);

        // Clean up the temporary file
        // fs::remove_file(temp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_encryption_consistency() {
        let password = "password123";
        let locker = AesLocker::new(password);

        // Create a temporary file with test data
        let temp_path = Path::new("testfile.txt");
        let original_data = b"Data consistency check";
        create_temp_file(temp_path.to_str().unwrap(), original_data).await.unwrap();

        // Lock (encrypt) the file
        locker.lock_inner(temp_path.to_path_buf(), password.to_string()).await.unwrap();

        // Read the encrypted file
        let encrypted_data = fs::read(temp_path).await.unwrap();

        // Check if encrypted data is not the same as the original data
        assert_ne!(original_data, &encrypted_data[..]);

        // Unlock (decrypt) the file
        locker.unlock_inner(temp_path.to_path_buf(), password.to_string()).await.unwrap();

        // Read the decrypted file
        let decrypted_data = fs::read(temp_path).await.unwrap();

        // Verify that the decrypted data matches the original data
        assert_eq!(original_data, &decrypted_data[..]);

        // Clean up the temporary file
        // fs::remove_file(temp_path).await.unwrap();
    }
}
